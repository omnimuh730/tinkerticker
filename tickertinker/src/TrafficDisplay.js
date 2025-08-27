import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api';

function TrafficDisplay({ isCapturing }) {
  const [trafficData, setTrafficData] = useState({ total_packets: 0, total_bytes: 0 });
  const [error, setError] = useState(null);

  useEffect(() => {
    let intervalId;
    if (isCapturing) {
      intervalId = setInterval(async () => {
        try {
          const result = await invoke('get_traffic_data');
          setTrafficData(result);
        } catch (err) {
          setError(err);
          console.error('Error getting traffic data:', err);
        }
      }, 500); // Poll every 500ms
    }

    return () => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    };
  }, [isCapturing]);

  if (error) {
    return <div>Error fetching traffic data: {error.toString()}</div>;
  }

  return (
    <div>
      <h2>Network Traffic</h2>
      <p>Total Packets: {trafficData.total_packets}</p>
      <p>Total Bytes: {trafficData.total_bytes}</p>
    </div>
  );
}

export default TrafficDisplay;
