#!/bin/bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

if [ -f /usr/local/mesh_services/meshagent/meshagent ]; then
  /usr/local/mesh_services/meshagent/meshagent -fulluninstall
fi

if [ -f /opt/ulrmm-mesh/meshagent ]; then
  /opt/ulrmm-mesh/meshagent -fulluninstall
fi

# the self-healing job goes first, it would bring the agent back
launchctl bootout system/identMacPlistLabel.selfheal 2>/dev/null
rm -f /Library/LaunchDaemons/identMacPlistLabel.selfheal.plist
launchctl bootout system /Library/LaunchDaemons/identMacPlistLabel.plist
rm -rf /usr/local/mesh_services
rm -rf /opt/ulrmm-mesh
rm -f identNixConf
rm -rf identNixDir
rm -f /Library/LaunchDaemons/identMacPlistLabel.plist
rm -f /Library/LaunchAgents/meshagent-agent.plist
