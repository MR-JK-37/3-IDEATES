import React from 'react'
import { View, Text, ScrollView } from 'react-native'

const Dashboard = () => {
  return (
    <ScrollView contentContainerStyle={{ padding: 16 }}>
      <Text style={{ fontSize: 20, fontWeight: '700' }}>CyberShield</Text>
      <Text style={{ marginTop: 8 }}>Live Threat Feed</Text>
      <View style={{ height: 12 }} />
      <Text>— No events (demo)</Text>
    </ScrollView>
  )
}

export default Dashboard
