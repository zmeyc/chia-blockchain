import logging
import asyncio
from pathlib import Path
from typing import Dict, Optional, Tuple, List, Callable, Set
import time
import concurrent

from blspy import G1Element

from chiapos import DiskProver
from src.consensus.constants import ConsensusConstants
from src.protocols import harvester_protocol
from src.server.outbound_message import Message
from src.types.proof_of_space import ProofOfSpace
from src.util.ints import uint8
from src.plotting.plot_tools import (
    load_plots,
    PlotInfo,
    remove_plot_directory,
    add_plot_directory,
    get_plot_directories,
)

log = logging.getLogger(__name__)


class Harvester:
    provers: Dict[Path, PlotInfo]
    failed_to_open_filenames: Dict[Path, int]
    no_key_filenames: Set[Path]
    farmer_public_keys: List[G1Element]
    pool_public_keys: List[G1Element]
    cached_challenges: List[harvester_protocol.NewChallenge]
    root_path: Path
    _is_shutdown: bool
    executor: concurrent.futures.ThreadPoolExecutor
    state_changed_callback: Optional[Callable]
    constants: ConsensusConstants
    _refresh_lock: asyncio.Lock

    def __init__(self, root_path: Path, constants: ConsensusConstants):
        self.root_path = root_path

        # From filename to prover
        self.provers = {}
        self.failed_to_open_filenames = {}
        self.no_key_filenames = set()

        self._is_shutdown = False
        self.farmer_public_keys = []
        self.pool_public_keys = []
        self.match_str = None
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=10)
        self.state_changed_callback = None
        self.server = None
        self.constants = constants
        self.cached_challenges = []
        self.log = log

    async def _start(self):
        self._refresh_lock = asyncio.Lock()

    def _close(self):
        self._is_shutdown = True
        self.executor.shutdown(wait=True)

    async def _await_closed(self):
        pass

    def _set_state_changed_callback(self, callback: Callable):
        self.state_changed_callback = callback

    def _state_changed(self, change: str):
        if self.state_changed_callback is not None:
            self.state_changed_callback(change)

    def _get_plots(self) -> Tuple[List[Dict], List[str], List[str]]:
        response_plots: List[Dict] = []
        for path, plot_info in self.provers.items():
            prover = plot_info.prover
            response_plots.append(
                {
                    "filename": str(path),
                    "size": prover.get_size(),
                    "plot-seed": prover.get_id(),
                    "pool_public_key": plot_info.pool_public_key,
                    "farmer_public_key": plot_info.farmer_public_key,
                    "plot_public_key": plot_info.plot_public_key,
                    "local_sk": plot_info.local_sk,
                    "file_size": plot_info.file_size,
                    "time_modified": plot_info.time_modified,
                }
            )

        return (
            response_plots,
            [str(s) for s, _ in self.failed_to_open_filenames.items()],
            [str(s) for s in self.no_key_filenames],
        )

    async def _refresh_plots(self):
        locked: bool = self._refresh_lock.locked()
        changed: bool = False
        async with self._refresh_lock:
            if not locked:
                # Avoid double refreshing of plots
                (
                    changed,
                    self.provers,
                    self.failed_to_open_filenames,
                    self.no_key_filenames,
                ) = load_plots(
                    self.provers,
                    self.failed_to_open_filenames,
                    self.farmer_public_keys,
                    self.pool_public_keys,
                    self.match_str,
                    self.root_path,
                )
        if changed:
            self._state_changed("plots")

    def _delete_plot(self, str_path: str):
        path = Path(str_path).resolve()
        if path in self.provers:
            del self.provers[path]

        # Remove absolute and relative paths
        if path.exists():
            path.unlink()

        self._state_changed("plots")
        return True

    async def _add_plot_directory(self, str_path: str) -> bool:
        add_plot_directory(str_path, self.root_path)
        await self._refresh_plots()
        return True

    async def _get_plot_directories(self) -> List[str]:
        return get_plot_directories(self.root_path)

    async def _remove_plot_directory(self, str_path: str) -> bool:
        remove_plot_directory(str_path, self.root_path)
        return True

    def _set_server(self, server):
        self.server = server

    async def _new_challenge(self, new_challenge: harvester_protocol.NewChallenge):
        """
        The harvester receives a new challenge from the farmer, and looks up the quality string
        for any proofs of space that are are found in the plots. If proofs are found, a
        ChallengeResponse message is sent for each of the proofs found.
        """

        if len(self.pool_public_keys) == 0 or len(self.farmer_public_keys) == 0:
            self.cached_challenges = self.cached_challenges[:5]
            self.cached_challenges.insert(0, new_challenge)
            return

        start = time.time()
        assert len(new_challenge.challenge_hash) == 32

        # Refresh plots to see if there are any new ones
        await self._refresh_plots()

        loop = asyncio.get_running_loop()

        def blocking_lookup(filename: Path, prover: DiskProver) -> Optional[List]:
            # Uses the DiskProver object to lookup qualities. This is a blocking call,
            # so it should be run in a threadpool.
            try:
                quality_strings = prover.get_qualities_for_challenge(
                    new_challenge.challenge_hash
                )
            except Exception:
                log.error("Error using prover object. Reinitializing prover object.")
                try:
                    self.prover = DiskProver(str(filename))
                    quality_strings = self.prover.get_qualities_for_challenge(
                        new_challenge.challenge_hash
                    )
                except Exception:
                    log.error(
                        f"Retry-Error using prover object on {filename}. Giving up."
                    )
                    quality_strings = None
            return quality_strings

        async def lookup_challenge(
            filename: Path, prover: DiskProver
        ) -> List[harvester_protocol.ChallengeResponse]:
            # Exectures a DiskProverLookup in a threadpool, and returns responses
            all_responses: List[harvester_protocol.ChallengeResponse] = []
            quality_strings = await loop.run_in_executor(
                self.executor, blocking_lookup, filename, prover
            )
            if quality_strings is not None:
                for index, quality_str in enumerate(quality_strings):
                    response: harvester_protocol.ChallengeResponse = (
                        harvester_protocol.ChallengeResponse(
                            new_challenge.challenge_hash,
                            str(filename),
                            uint8(index),
                            quality_str,
                            prover.get_size(),
                        )
                    )
                    all_responses.append(response)
            return all_responses

        awaitables = []
        for filename, plot_info in self.provers.items():
            if filename.exists() and ProofOfSpace.can_create_proof(
                plot_info.prover.get_id(),
                new_challenge.challenge_hash,
                self.constants.NUMBER_ZERO_BITS_CHALLENGE_SIG,
            ):
                awaitables.append(lookup_challenge(filename, plot_info.prover))

        # Concurrently executes all lookups on disk, to take advantage of multiple disk parallelism
        total_proofs_found = 0
        for sublist_awaitable in asyncio.as_completed(awaitables):
            for response in await sublist_awaitable:
                total_proofs_found += 1
                msg = Message("challenge_response", response)
                yield msg
        log.info(
            f"{len(awaitables)} plots were eligible for farming {new_challenge.challenge_hash.hex()[:10]}..."
            f" Found {total_proofs_found} proofs. Time: {time.time() - start}. "
            f"Total {len(self.provers)} plots"
        )
