import React, { useState } from 'react';
import InterfaceSelector from './InterfaceSelector';
import CaptureControls from './CaptureControls';
import TrafficDisplay from './TrafficDisplay';

function App() {
  const [selectedInterface, setSelectedInterface] = useState('');
  const [isCapturing, setIsCapturing] = useState(false);

  const handleSelectInterface = (iface) => {
    setSelectedInterface(iface);
  };

  const handleStartCapture = () => {
    setIsCapturing(true);
  };

  const handleStopCapture = () => {
    setIsCapturing(false);
  };

  return (
    <div>
      <h1>TickerTinker Network Monitor</h1>
      <InterfaceSelector onSelectInterface={handleSelectInterface} />
      <CaptureControls
        selectedInterface={selectedInterface}
        onStart={handleStartCapture}
        onStop={handleStopCapture}
      />
      <TrafficDisplay isCapturing={isCapturing} />
    </div>
  );
}

export default App;