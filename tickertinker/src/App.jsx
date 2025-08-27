import React, { useState, useEffect } from 'react';
import InterfaceSelector from './InterfaceSelector';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import CaptureControls from './CaptureControls';
import TrafficDisplay from './TrafficDisplay';

function App() {
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSelectInterface = (iface) => {
    setSelectedInterface(iface);
    setIsCapturing(false); // Stop capture when interface changes
  };

  const handleStartCapture = () => {
    setIsLoading(true);
    // For now, hardcode a device name. You'll want to use the selectedInterface here.
    invoke('start_capture', { deviceName: selectedInterface })
      .then(() => {
        setIsCapturing(true);
        setIsLoading(false);
      })
      .catch((error) => {
 setError(error);
        setIsLoading(false);
      });
  };

  const handleStopCapture = () => {
    setIsLoading(true);
    invoke('stop_capture')
      .then(() => {
        setIsCapturing(false);
        setIsLoading(false);
      })
      .catch((error) => {
 setError(error);
      });
  };

  const handleGetTrafficData = () => {
    invoke('get_traffic_data')
      .then((data) => {
        console.log('Fetched traffic data:', data);
        setTrafficData(data); // Update state with fetched data
      })
      .catch((error) => {
 setError(error);
      });
  };

  useEffect(() => {
    let unlisten;
    const setupListener = async () => {

      unlisten = await listen('traffic-update', (event) => {
 setTrafficData(event.payload);
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
 {error && <p style={{ color: 'red' }}>Error: {error}</p>}
      <InterfaceSelector onSelectInterface={handleSelectInterface} />
      <CaptureControls
 selectedInterface={selectedInterface}
 onStart={handleStartCapture}
 onStop={handleStopCapture}
 isCapturing={isCapturing}
 />
      <TrafficDisplay trafficData={trafficData} />
      <button onClick={handleGetTrafficData}>Get Traffic Data</button>
      {error && <p style={{ color: 'red' }}>Error: {error}</p>}
    </div>
  );
}
export default App;