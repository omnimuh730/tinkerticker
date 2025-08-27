import React, { useState, useEffect } from 'react';
import InterfaceSelector from './InterfaceSelector';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import CaptureControls from './CaptureControls';
import TrafficDisplay from './TrafficDisplay';

function App() {
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);

  const handleSelectInterface = (iface) => {
    setSelectedInterface(iface);
    setIsCapturing(false); // Stop capture when interface changes
  };

  const handleStartCapture = () => {
    // For now, hardcode a device name. You'll want to use the selectedInterface here.
    invoke('start_capture', { deviceName: selectedInterface })
      .then(() => setIsCapturing(true))
      .catch((error) => {
        console.error('Error starting capture:', error);
        // Handle the error appropriately in the UI
      });
  };

  const handleStopCapture = () => {
 invoke('stop_capture')
 .then(() => setIsCapturing(false))
 .catch((error) => {
 console.error('Error stopping capture:', error);
      });
  };

  useEffect(() => {
    const [trafficData, setTrafficData] = useState(null);
    let unlisten;
    const setupListener = async () => {

      unlisten = await listen('traffic-update', (event) => {
        console.log('Received traffic data:', event.payload);
        // You'll likely want to update state with this data to display it
      });
    };

    setupListener();

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, []); // Empty dependency array means this effect runs once on mount and cleans up on unmount

  return (
    <div>
      <h1>TickerTinker Network Monitor</h1>
      <InterfaceSelector onSelectInterface={handleSelectInterface} />
 <CaptureControls
 selectedInterface={selectedInterface}
 onStart={handleStartCapture}
 onStop={handleStopCapture}
 />
      <TrafficDisplay trafficData={trafficData} />
    </div>
  );
}

export default App;