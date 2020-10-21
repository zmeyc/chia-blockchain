import asyncio
import concurrent
import functools
import logging
import traceback
import time
import random
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Tuple, Callable
import aiosqlite
from src.consensus.constants import ConsensusConstants
from src.full_node.block_store import BlockStore
from src.full_node.blockchain import Blockchain, ReceiveBlockResult
from src.full_node.coin_store import CoinStore
from src.full_node.full_node_store import FullNodeStore
from src.full_node.mempool_manager import MempoolManager
from src.full_node.sync_blocks_processor import SyncBlocksProcessor
from src.full_node.sync_peers_handler import SyncPeersHandler
from src.full_node.sync_store import SyncStore
from src.protocols import (
    farmer_protocol,
    full_node_protocol,
    timelord_protocol,
    wallet_protocol,
)
from src.server.node_discovery import FullNodePeers
from src.server.outbound_message import Delivery, Message, NodeType, OutboundMessage
from src.server.server import ChiaServer
from src.server.ws_connection import WSChiaConnection
from src.types.challenge import Challenge
from src.types.full_block import FullBlock
from src.types.header import Header

from src.types.sized_bytes import bytes32

from src.util.errors import ConsensusError
from src.util.ints import uint32, uint64, uint128
from src.util.path import mkdir, path_from_root

OutboundMessageGenerator = AsyncGenerator[OutboundMessage, None]


class FullNode:
    block_store: BlockStore
    full_node_store: FullNodeStore
    # full_node_peers: FullNodePeers
    sync_store: SyncStore
    coin_store: CoinStore
    mempool_manager: MempoolManager
    connection: aiosqlite.Connection
    sync_peers_handler: Optional[SyncPeersHandler]
    blockchain: Blockchain
    config: Dict
    server: Optional[ChiaServer]
    log: logging.Logger
    constants: ConsensusConstants
    _shut_down: bool
    root_path: Path
    state_changed_callback: Optional[Callable]

    def __init__(
        self,
        config: Dict,
        root_path: Path,
        consensus_constants: ConsensusConstants,
        name: str = None,
    ):
        self.root_path = root_path
        self.config = config
        self.server = None
        self._shut_down = False  # Set to true to close all infinite loops
        self.constants = consensus_constants
        self.sync_peers_handler = None
        if name:
            self.log = logging.getLogger(name)
        else:
            self.log = logging.getLogger(__name__)

        self.db_path = path_from_root(root_path, config["database_path"])
        mkdir(self.db_path.parent)

    def _set_state_changed_callback(self, callback: Callable):
        self.state_changed_callback = callback

    async def _start(self):
        # create the store (db) and full node instance
        self.connection = await aiosqlite.connect(self.db_path)
        self.block_store = await BlockStore.create(self.connection)
        self.full_node_store = await FullNodeStore.create(self.connection)
        self.sync_store = await SyncStore.create()
        self.coin_store = await CoinStore.create(self.connection)
        self.log.info("Initializing blockchain from disk")
        self.blockchain = await Blockchain.create(
            self.coin_store, self.block_store, self.constants
        )
        self.log.info(
            f"Blockchain initialized to tips at {[t.height for t in self.blockchain.get_current_tips()]}"
        )

        self.mempool_manager = MempoolManager(self.coin_store, self.constants)
        await self.mempool_manager.new_tips(await self.blockchain.get_full_tips())
        self.state_changed_callback = None

        uncompact_interval = self.config["send_uncompact_interval"]
        if uncompact_interval > 0:
            self.broadcast_uncompact_task = asyncio.create_task(
                self.broadcast_uncompact_blocks(uncompact_interval)
            )

        for ((_, _), block) in (
            await self.full_node_store.get_unfinished_blocks()
        ).items():
            if block.height > self.full_node_store.get_unfinished_block_leader()[0]:
                self.full_node_store.set_unfinished_block_leader(
                    (block.height, 999999999999)
                )

    def _set_server(self, server: ChiaServer):
        self.server = server
        try:
            self.full_node_peers = FullNodePeers(
                self.server,
                self.root_path,
                self.config["target_peer_count"]
                - self.config["target_outbound_peer_count"],
                self.config["target_outbound_peer_count"],
                self.config["peer_db_path"],
                self.config["introducer_peer"],
                self.config["peer_connect_interval"],
                self.log,
            )
            asyncio.create_task(self.full_node_peers.start())
        except Exception as e:
            self.log.error(f"Exception in peer discovery: {e}")

    def _state_changed(self, change: str):
        if self.state_changed_callback is not None:
            self.state_changed_callback(change)

    async def _send_tips_to_farmers(self):
        """
        Sends all of the current heads to all farmer peers. Also sends the latest
        estimated proof of time rate, so farmer can calulate which proofs are good.
        """

        requests: List[farmer_protocol.ProofOfSpaceFinalized] = []
        async with self.blockchain.lock:
            tips: List[Header] = self.blockchain.get_current_tips()
            for tip in tips:
                full_tip: Optional[FullBlock] = await self.block_store.get_block(
                    tip.header_hash
                )
                assert full_tip is not None
                challenge: Optional[Challenge] = self.blockchain.get_challenge(full_tip)
                assert challenge is not None
                challenge_hash = challenge.get_hash()
                if tip.height > 0:
                    difficulty: uint64 = self.blockchain.get_next_difficulty(
                        self.blockchain.headers[tip.prev_header_hash]
                    )
                else:
                    difficulty = uint64(tip.weight)
                requests.append(
                    farmer_protocol.ProofOfSpaceFinalized(
                        challenge_hash, tip.height, tip.weight, difficulty
                    )
                )
            full_block: Optional[FullBlock] = await self.block_store.get_block(
                tips[0].header_hash
            )
            assert full_block is not None
            proof_of_time_min_iters: uint64 = self.blockchain.get_next_min_iters(
                full_block
            )
            proof_of_time_rate: uint64 = uint64(
                proof_of_time_min_iters
                * self.constants.MIN_ITERS_PROPORTION
                // (self.constants.BLOCK_TIME_TARGET)
            )
        rate_update = farmer_protocol.ProofOfTimeRate(proof_of_time_rate)
        messages = [Message("proof_of_time_rate", rate_update)]

        for request in requests:
            messages.append(Message("proof_of_space_finalized", request))

        await self.server.send_to_all(messages, NodeType.FARMER)

    async def _send_challenges_to_timelords(
        self, time_lords: List[WSChiaConnection] = None
    ):
        """
        Sends all of the current heads (as well as Pos infos) to all timelord peers.
        """
        full_messages = []
        timelord_messages = []

        challenge_requests: List[timelord_protocol.ChallengeStart] = []
        pos_info_requests: List[timelord_protocol.ProofOfSpaceInfo] = []
        tips: List[Header] = self.blockchain.get_current_tips()
        tips_blocks: List[Optional[FullBlock]] = [
            await self.block_store.get_block(tip.header_hash) for tip in tips
        ]
        for tip in tips_blocks:
            assert tip is not None
            challenge = self.blockchain.get_challenge(tip)
            assert challenge is not None
            challenge_requests.append(
                timelord_protocol.ChallengeStart(challenge.get_hash(), tip.weight)
            )

        tip_hashes = [tip.header_hash for tip in tips]
        tip_infos = [
            (tup[0], tup[1])
            for tup in list(
                (await self.full_node_store.get_unfinished_blocks()).items()
            )
            if tup[1].prev_header_hash in tip_hashes
        ]
        for ((chall, iters), _) in tip_infos:
            pos_info_requests.append(timelord_protocol.ProofOfSpaceInfo(chall, iters))

        # Sends our best unfinished block (proof of space) to peer
        for ((_, iters), block) in sorted(tip_infos, key=lambda t: t[0][1]):
            if block.height < self.full_node_store.get_unfinished_block_leader()[0]:
                continue
            unfinished_block_msg = full_node_protocol.NewUnfinishedBlock(
                block.prev_header_hash, iters, block.header_hash
            )
            full_messages.append(Message("new_unfinished_block", unfinished_block_msg))
            break
        for challenge_msg in challenge_requests:
            timelord_messages.append(Message("challenge_start", challenge_msg))
        for pos_info_msg in pos_info_requests:
            timelord_messages.append(Message("proof_of_space_info", pos_info_msg))

        if self.server is not None:
            await self.server.send_to_all(timelord_messages, NodeType.TIMELORD)
            await self.server.send_to_all(full_messages, NodeType.FULL_NODE)

    async def _on_connect(self, connection: WSChiaConnection):
        """
        Whenever we connect to another node / wallet, send them our current heads. Also send heads to farmers
        and challenges to timelords.
        """
        if connection.connection_type is NodeType.FULL_NODE:
            tips: List[Header] = self.blockchain.get_current_tips()
            for t in tips:
                request = full_node_protocol.NewTip(t.height, t.weight, t.header_hash)
                msg = Message("new_tip", request)
                await connection.send_message(msg)

            # Send filter to node and request mempool items that are not in it
            my_filter = self.mempool_manager.get_filter()
            mempool_request = full_node_protocol.RequestMempoolTransactions(my_filter)
            msg = Message("request_mempool_transactions", mempool_request)
            await connection.send_message(msg)
        elif connection.connection_type is NodeType.WALLET:
            # If connected to a wallet, send the LCA
            lca = self.blockchain.lca_block
            new_lca = wallet_protocol.NewLCA(lca.header_hash, lca.height, lca.weight)
            msg = Message("new_lca", new_lca)
            await connection.send_message(msg)
        elif connection.connection_type is NodeType.TIMELORD:
            await self._send_challenges_to_timelords()
        elif connection.connection_type is NodeType.FARMER:
            await self._send_tips_to_farmers()

    async def _on_disconnect(self, connection: WSChiaConnection):
        self.log.info("peer disconnected")

    def _num_needed_peers(self) -> int:
        assert self.server is not None
        assert self.server.global_connections is not None
        diff = self.config["target_peer_count"] - len(self.server.global_connections)
        return diff if diff >= 0 else 0

    def _close(self):
        self._shut_down = True
        self.blockchain.shut_down()
        asyncio.create_task(self.full_node_peers.close())

    async def _await_closed(self):
        await self.connection.close()

    async def _sync(self):
        """
        Performs a full sync of the blockchain.
            - Check which are the heaviest tips
            - Request headers for the heaviest
            - Find the fork point to see where to start downloading headers
            - Verify the weight of the tip, using the headers
            - Download all blocks
            - Disconnect peers that provide invalid blocks or don't have the blocks
        """
        self.log.info("Starting to perform sync with peers.")
        self.log.info("Waiting to receive tips from peers.")
        self.sync_peers_handler = None
        self.sync_store.set_waiting_for_tips(True)
        # TODO: better way to tell that we have finished receiving tips
        # TODO: fix DOS issue. Attacker can request syncing to an invalid blockchain
        await asyncio.sleep(2)
        highest_weight: uint128 = uint128(0)
        tip_block: Optional[FullBlock] = None
        tip_height = 0
        sync_start_time = time.time()

        if self.server is None:
            return

        # Based on responses from peers about the current heads, see which head is the heaviest
        # (similar to longest chain rule).
        self.sync_store.set_waiting_for_tips(False)

        potential_tips: List[
            Tuple[bytes32, FullBlock]
        ] = self.sync_store.get_potential_tips_tuples()
        self.log.info(f"Have collected {len(potential_tips)} potential tips")
        if self._shut_down:
            return

        for header_hash, potential_tip_block in potential_tips:
            if potential_tip_block.proof_of_time is None:
                raise ValueError(
                    f"Invalid tip block {potential_tip_block.header_hash} received"
                )
            if potential_tip_block.weight > highest_weight:
                highest_weight = potential_tip_block.weight
                tip_block = potential_tip_block
                tip_height = potential_tip_block.height
        if highest_weight <= max(
            [t.weight for t in self.blockchain.get_current_tips()]
        ):
            self.log.info("Not performing sync, already caught up.")
            return

        assert tip_block
        self.log.info(
            f"Tip block {tip_block.header_hash} tip height {tip_block.height}"
        )

        self.sync_store.set_potential_hashes_received(asyncio.Event())

        sleep_interval = 10
        total_time_slept = 0

        # TODO: verify weight here once we have the correct protocol messages (interative flyclient)
        while True:
            if total_time_slept > 30:
                raise TimeoutError("Took too long to fetch header hashes.")
            if self._shut_down:
                return None
            # Download all the header hashes and find the fork point
            request = full_node_protocol.RequestAllHeaderHashes(tip_block.header_hash)
            msg = Message("request_all_header_hashes", request)
            await self.server.send_to_all([msg], NodeType.FULL_NODE)
            try:
                phr = self.sync_store.get_potential_hashes_received()
                assert phr is not None
                await asyncio.wait_for(
                    phr.wait(),
                    timeout=sleep_interval,
                )
                break
            # https://github.com/python/cpython/pull/13528
            except (concurrent.futures.TimeoutError, asyncio.TimeoutError):
                total_time_slept += sleep_interval
                self.log.warning("Did not receive desired header hashes")

        # Finding the fork point allows us to only download headers and blocks from the fork point
        header_hashes = self.sync_store.get_potential_hashes()

        async with self.blockchain.lock:
            # Lock blockchain so we can copy over the headers without any reorgs
            fork_point_height: uint32 = self.blockchain.find_fork_point_alternate_chain(
                header_hashes
            )

        fork_point_hash: bytes32 = header_hashes[fork_point_height]
        self.log.info(f"Fork point: {fork_point_hash} at height {fork_point_height}")

        peers = [
            con.peer_node_id
            for id, con in self.server.global_connections.items()
            if (
                con.peer_node_id is not None
                and con.connection_type == NodeType.FULL_NODE
            )
        ]

        self.sync_peers_handler = SyncPeersHandler(
            self.sync_store, peers, fork_point_height, self.blockchain
        )

        # Start processing blocks that we have received (no block yet)
        block_processor = SyncBlocksProcessor(
            self.sync_store,
            fork_point_height,
            uint32(tip_height),
            self.blockchain,
        )
        block_processor_task = asyncio.create_task(block_processor.process())
        lca = self.blockchain.lca_block
        while not self.sync_peers_handler.done():
            # Periodically checks for done, timeouts, shutdowns, new peers or disconnected peers.
            if self._shut_down:
                block_processor.shut_down()
                break
            if block_processor_task.done():
                break

            cur_peers = [
                con.peer_node_id
                for id, con in self.server.global_connections.items()
                if (
                    con.peer_node_id is not None
                    and con.connection_type == NodeType.FULL_NODE
                )
            ]
            for node_id in cur_peers:
                if node_id not in peers:
                    self.sync_peers_handler.new_node_connected(node_id)
            for node_id in peers:
                if node_id not in cur_peers:
                    # Disconnected peer, removes requests that are being sent to it
                    self.sync_peers_handler.node_disconnected(node_id)
            peers = cur_peers

            requests: List[
                OutboundMessage
            ] = await self.sync_peers_handler._add_to_request_sets()

            for req in requests:
                msg = req.message
                node_id = req.specific_peer_node_id
                await self.server.send_to_specific([msg], node_id)

            new_lca = self.blockchain.lca_block
            if new_lca != lca:
                new_lca_req = wallet_protocol.NewLCA(
                    new_lca.header_hash,
                    new_lca.height,
                    new_lca.weight,
                )
                msg = Message("new_lca", new_lca_req)
                await self.server.send_to_all([msg], NodeType.WALLET)

            self._state_changed("block")
            await asyncio.sleep(5)

        # Awaits for all blocks to be processed, a timeout to happen, or the node to shutdown
        await block_processor_task
        block_processor_task.result()  # If there was a timeout, this will raise TimeoutError
        if self._shut_down:
            return

        current_tips = self.blockchain.get_current_tips()
        assert max([h.height for h in current_tips]) == tip_height

        self.full_node_store.set_proof_of_time_estimate_ips(
            (
                self.blockchain.get_next_min_iters(tip_block)
                * self.constants.MIN_ITERS_PROPORTION
                // self.constants.BLOCK_TIME_TARGET
            )
        )

        self.log.info(
            f"Finished sync up to height {tip_height}. Total time: "
            f"{round((time.time() - sync_start_time)/60, 2)} minutes."
        )

    async def _finish_sync(self):
        """
        Finalize sync by setting sync mode to False, clearing all sync information, and adding any final
        blocks that we have finalized recently.
        """
        if self.server is None:
            return

        potential_fut_blocks = (self.sync_store.get_potential_future_blocks()).copy()
        self.sync_store.set_sync_mode(False)

        async with self.blockchain.lock:
            await self.sync_store.clear_sync_info()
            await self.blockchain.recreate_diff_stores()

        for block in potential_fut_blocks:
            if self._shut_down:
                return
            await self._respond_block(full_node_protocol.RespondBlock(block))

        # Update farmers and timelord with most recent information
        await self._send_challenges_to_timelords()
        await self._send_tips_to_farmers()

        lca = self.blockchain.lca_block
        new_lca = wallet_protocol.NewLCA(lca.header_hash, lca.height, lca.weight)
        msg = Message("new_lca", new_lca)
        await self.server.send_to_all([msg], NodeType.WALLET)
        self._state_changed("block")

    # Periodically scans for blocks with non compact proof of time
    # (witness_type != 0) and sends them to the connected timelords.
    async def broadcast_uncompact_blocks(
        self, uncompact_interval, delivery: Delivery = Delivery.BROADCAST
    ):
        min_height = 1
        while not self._shut_down:
            while self.sync_store.get_sync_mode():
                if self._shut_down:
                    return
                await asyncio.sleep(30)

            broadcast_list: List = []
            new_min_height = None
            max_height = self.blockchain.lca_block.height
            uncompact_blocks = 0
            self.log.info("Scanning the blockchain for uncompact blocks.")

            for h in range(min_height, max_height):
                if self._shut_down:
                    return
                blocks: List[FullBlock] = await self.block_store.get_blocks_at(
                    [uint32(h)]
                )
                header_hash = self.blockchain.height_to_hash[uint32(h)]
                for block in blocks:
                    assert block.proof_of_time is not None
                    if block.header_hash != header_hash:
                        continue

                    if block.proof_of_time.witness_type != 0:
                        challenge_msg = timelord_protocol.ChallengeStart(
                            block.proof_of_time.challenge_hash,
                            block.weight,
                        )
                        pos_info_msg = timelord_protocol.ProofOfSpaceInfo(
                            block.proof_of_time.challenge_hash,
                            block.proof_of_time.number_of_iterations,
                        )
                        broadcast_list.append(
                            (
                                challenge_msg,
                                pos_info_msg,
                            )
                        )
                        # Scan only since the first uncompact block we know about.
                        # No block earlier than this will be uncompact in the future,
                        # unless a reorg happens. The range to scan next time
                        # is always at least 200 blocks, to protect against reorgs.
                        if uncompact_blocks == 0 and h <= max(1, max_height - 200):
                            new_min_height = h
                        uncompact_blocks += 1

            if new_min_height is None:
                # Every block is compact, but we still keep at least 200 blocks to iterate.
                new_min_height = max(1, max_height - 200)
            min_height = new_min_height

            self.log.info(f"Collected {uncompact_blocks} uncompact blocks.")
            if len(broadcast_list) > 50:
                random.shuffle(broadcast_list)
                broadcast_list = broadcast_list[:50]
            if self.sync_store.get_sync_mode():
                continue
            if self.server is not None:
                for challenge_msg, pos_info_msg in broadcast_list:
                    msg = Message("challenge_start", challenge_msg)
                    await self.server.send_to_all([msg], NodeType.TIMELORD)
                    msg = Message("proof_of_space_info", pos_info_msg)
                    await self.server.send_to_all([msg], NodeType.TIMELORD)
            self.log.info(
                f"Broadcasted {len(broadcast_list)} uncompact blocks to timelords."
            )
            await asyncio.sleep(uncompact_interval)

    async def _respond_block(self, respond_block: full_node_protocol.RespondBlock):
        """
        Receive a full block from a peer full node (or ourselves).
        """
        if self.server is None:
            return

        if self.sync_store.get_sync_mode():
            # This is a tip sent to us by another peer
            if self.sync_store.get_waiting_for_tips():
                # Add the block to our potential tips list
                self.sync_store.add_potential_tip(respond_block.block)
                return

            # This is a block we asked for during sync
            if self.sync_peers_handler is not None:
                resp: List[OutboundMessage] = await self.sync_peers_handler.new_block(
                    respond_block.block
                )
                for req in resp:
                    type = req.peer_type
                    node_id = req.specific_peer_node_id
                    message = req.message
                    if node_id is None:
                        await self.server.send_to_all([message], type)
                    else:
                        await self.server.send_to_specific([message], node_id)

        # Adds the block to seen, and check if it's seen before (which means header is in memory)
        header_hash = respond_block.block.header.get_hash()
        if self.blockchain.contains_block(header_hash):
            return

        prev_lca = self.blockchain.lca_block

        async with self.blockchain.lock:
            # Tries to add the block to the blockchain
            added, replaced, error_code = await self.blockchain.receive_block(
                respond_block.block, False, None, sync_mode=False
            )
            if added == ReceiveBlockResult.ADDED_TO_HEAD:
                await self.mempool_manager.new_tips(
                    await self.blockchain.get_full_tips()
                )

        if added == ReceiveBlockResult.ALREADY_HAVE_BLOCK:
            return
        elif added == ReceiveBlockResult.INVALID_BLOCK:
            self.log.error(
                f"Block {header_hash} at height {respond_block.block.height} is invalid with code {error_code}."
            )
            assert error_code is not None
            raise ConsensusError(error_code, header_hash)

        elif added == ReceiveBlockResult.DISCONNECTED_BLOCK:
            self.log.info(
                f"Disconnected block {header_hash} at height {respond_block.block.height}"
            )
            tip_height = min(
                [head.height for head in self.blockchain.get_current_tips()]
            )

            if (
                respond_block.block.height
                > tip_height + self.config["sync_blocks_behind_threshold"]
            ):
                async with self.blockchain.lock:
                    if self.sync_store.get_sync_mode():
                        return
                    await self.sync_store.clear_sync_info()
                    self.sync_store.add_potential_tip(respond_block.block)
                    self.sync_store.set_sync_mode(True)
                self.log.info(
                    f"We are too far behind this block. Our height is {tip_height} and block is at "
                    f"{respond_block.block.height}"
                )
                try:
                    # Performs sync, and catch exceptions so we don't close the connection
                    await self._sync()
                except asyncio.CancelledError:
                    self.log.error("Syncing failed, CancelledError")
                except Exception as e:
                    tb = traceback.format_exc()
                    self.log.error(f"Error with syncing: {e} {tb}")
                finally:
                    await self._finish_sync()

            elif respond_block.block.height >= tip_height - 3:
                self.log.info(
                    f"We have received a disconnected block at height {respond_block.block.height}, "
                    f"current tip is {tip_height}"
                )
                msg = Message(
                    "request_block",
                    full_node_protocol.RequestBlock(
                        uint32(respond_block.block.height - 1),
                        respond_block.block.prev_header_hash,
                    ),
                )
                await self.server.send_to_all([msg], NodeType.FULL_NODE)
                self.full_node_store.add_disconnected_block(respond_block.block)
            return
        elif added == ReceiveBlockResult.ADDED_TO_HEAD:
            # Only propagate blocks which extend the blockchain (becomes one of the heads)
            self.log.info(
                f"Updated heads, new heights: {[b.height for b in self.blockchain.get_current_tips()]}"
            )

            difficulty = self.blockchain.get_next_difficulty(
                self.blockchain.headers[respond_block.block.prev_header_hash]
            )
            next_vdf_min_iters = self.blockchain.get_next_min_iters(respond_block.block)
            next_vdf_ips = uint64(
                next_vdf_min_iters
                * self.constants.MIN_ITERS_PROPORTION
                // self.constants.BLOCK_TIME_TARGET
            )
            self.log.info(f"Difficulty {difficulty} IPS {next_vdf_ips}")
            if next_vdf_ips != self.full_node_store.get_proof_of_time_estimate_ips():
                self.full_node_store.set_proof_of_time_estimate_ips(next_vdf_ips)
                rate_update = farmer_protocol.ProofOfTimeRate(next_vdf_ips)
                self.log.info(f"Sending proof of time rate {next_vdf_ips}")
                msg = Message("proof_of_time_rate", rate_update)
                await self.server.send_to_all([msg], NodeType.FARMER)
                # Occasionally clear the seen list to keep it small
                await self.full_node_store.clear_seen_unfinished_blocks()

            challenge: Optional[Challenge] = self.blockchain.get_challenge(
                respond_block.block
            )
            assert challenge is not None
            challenge_hash: bytes32 = challenge.get_hash()
            farmer_request = farmer_protocol.ProofOfSpaceFinalized(
                challenge_hash,
                respond_block.block.height,
                respond_block.block.weight,
                difficulty,
            )
            timelord_request = timelord_protocol.ChallengeStart(
                challenge_hash,
                respond_block.block.weight,
            )
            # Tell timelord to stop previous challenge and start with new one
            msg = Message("challenge_start", timelord_request)
            await self.server.send_to_all([msg], NodeType.TIMELORD)
            # Tell peers about the new tip
            msg = Message(
                "new_tip",
                full_node_protocol.NewTip(
                    respond_block.block.height,
                    respond_block.block.weight,
                    respond_block.block.header_hash,
                ),
            )
            await self.server.send_to_all([msg], NodeType.FULL_NODE)
            # Tell peers about the tip that was removed (if one was removed)
            if replaced is not None:
                msg = Message(
                    "removing_tip",
                    full_node_protocol.RemovingTip(replaced.header_hash),
                )
                await self.server.send_to_all([msg], NodeType.FULL_NODE)

            # Tell peer wallets about the new LCA, if it changed
            new_lca = self.blockchain.lca_block
            if new_lca != prev_lca:
                new_lca_req = wallet_protocol.NewLCA(
                    new_lca.header_hash,
                    new_lca.height,
                    new_lca.weight,
                )
                msg = Message("new_lca", new_lca_req)
                await self.server.send_to_all([msg], NodeType.WALLET)

            # Tell farmer about the new block
            msg = Message("proof_of_space_finalized", farmer_request)
            await self.server.send_to_all([msg], NodeType.FARMER)

        elif added == ReceiveBlockResult.ADDED_AS_ORPHAN:
            self.log.info(
                f"Received orphan block of height {respond_block.block.height}"
            )
        else:
            # Should never reach here, all the cases are covered
            raise RuntimeError(f"Invalid result from receive_block {added}")

        # This code path is reached if added == ADDED_AS_ORPHAN or ADDED_TO_HEAD
        next_block: Optional[
            FullBlock
        ] = self.full_node_store.get_disconnected_block_by_prev(
            respond_block.block.header_hash
        )

        # Recursively process the next block if we have it
        if next_block is not None:
            await self._respond_block(full_node_protocol.RespondBlock(next_block))

        # Removes all temporary data for old blocks
        lowest_tip = min(tip.height for tip in self.blockchain.get_current_tips())
        clear_height = uint32(max(0, lowest_tip - 30))
        self.full_node_store.clear_candidate_blocks_below(clear_height)
        self.full_node_store.clear_disconnected_blocks_below(clear_height)
        await self.full_node_store.clear_unfinished_blocks_below(clear_height)
        self._state_changed("block")
