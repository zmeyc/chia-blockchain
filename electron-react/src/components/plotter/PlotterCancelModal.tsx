import React from 'react';
import { Trans } from '@lingui/react';
import {
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from '@material-ui/core';

type Props = {
  isOpen: boolean;
  onClose: (cancelPlotting?: boolean) => void;
};

export default function PlotterCancelModal(props: Props) {
  const { onClose, isOpen } = props;

  function handleKeepPlotting() {
    onClose();
  }

  function handleCancelPlotting() {
    onClose(true);
  }

  return (
    <Dialog
      open={isOpen}
      onClose={() => handleKeepPlotting()}
      aria-labelledby="alert-dialog-title"
      aria-describedby="alert-dialog-description"
    >
      <DialogTitle id="alert-dialog-title">
        <Trans id="PlotterCancelModal.title">Cancel Plotting?</Trans>
      </DialogTitle>
      <DialogContent>
        <DialogContentText id="alert-dialog-description">
          <Trans id="PlotterCancelModal.description">
            Are you sure you want to cancel plotting?
          </Trans>
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancelPlotting} color="secondary">
          <Trans id="PlotterCancelModal.cancelPlotting">Cancel Plotting</Trans>
        </Button>
        <Button onClick={handleKeepPlotting} color="primary" autoFocus>
          <Trans id="PlotterCancelModal.keepPlotting">Keep Plotting</Trans>
        </Button>
      </DialogActions>
    </Dialog>
  );
}
