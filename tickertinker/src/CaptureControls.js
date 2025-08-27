import React from 'react';
import { invoke } from '@tauri-apps/api';

function CaptureControls({ selectedInterface, onStart, onStop }) {
  const handleStartCapture = async () => {
    if (selectedInterface) {
      try {
        await invoke('start_capture', { interfaceName: selectedInterface });
        onStart();
      } catch (err) {
        console.error('Error starting capture:', err);
      }
    }
  };

  const handleStopCapture = async () => {
    try {
      await invoke('stop_capture');
      onStop();
    } catch (err) {
      console.error('Error stopping capture:', err);
    }
  };

  return (
    <div>
      <h2>Capture Controls</h2>
      <button onClick={handleStartCapture} disabled={!selectedInterface}>
        Start Capture
      </button>
      <button onClick={handleStopCapture}>Stop Capture</button>
    </div>
  );
}

export default CaptureControls;
