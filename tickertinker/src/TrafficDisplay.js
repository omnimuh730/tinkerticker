import React from 'react';

function TrafficDisplay({ trafficData }) {
  // For now, just display the raw data
  // You'll want to format this data for better display later
  console.log("Traffic data structure:", trafficData);

  if (!trafficData) {
    return <p>No traffic data yet.</p>;
  }

  return (
    <div>
      <h2>Network Traffic Data</h2>
      {/* Display some key information. Adjust based on the actual structure of trafficData */}
      <p>Total Packets: {trafficData.total_packets}</p>
      {/* You can add more details here based on the trafficData structure */}
    </div>
  );
}

export default TrafficDisplay;
