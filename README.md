# Velociraptor MCP
Velociraptor MCP is a POC Model Context Protocol bridge for exposing LLMs to MCP clients.

Initial version has several Windows orientated triage tools deployed. Best use is querying usecase to target machine name.

e.g 

`can you give me all network connections on MACHINENAME and look for suspicious processes?`

`can you tell me which artifacts target the USN journal`




## Installation
### 1. Setup an API account
https://docs.velociraptor.app/docs/server_automation/server_api/

Generate an api config file:

`velociraptor --config /etc/velociraptor/server.config.yaml config api_client --name api --role administrator,api api_client.yaml`

### 2. Clone mcp-velociraptor repo and test API 

- copy api_client.yaml to preferred config location and ensure configuration correct (pointing to appropriate IP address).
- modify test_api.py to appropriate location.
- Run test_api.py to confirm working
- Modify mcp_velociraptor_bridge.py to correct API config

### 3. Connect to Claude desktop or MCP client of choice

The easiest configuration is to run your venv python directly calling mcp_velociraptor_bridge.
```{
  "mcpServers": {
    "velociraptor": {
      "command": "/path/to/venv/bin/python",
      "args": [
        "/path/to/mcp_velociraptor_bridge.py"
      ]
    }
  }
}
```

![image](https://github.com/user-attachments/assets/3e810f03-ca74-4757-b5dc-89d4e8f8aef6)


### 3. Caveats

Due to the nature of DFIR, results depend on amount of data returned, model use and context window.

I have included a function to find artifacts and dynamically create collections but had mixed results.
I have been pleasantly surprised with some results and disappointed when running other collections that cause lots of rows.

Please let me know how you go and feel free to add PR!


`can you give me all network connections on MACHINENAME and look for suspicious processes?`
<img alt="image" src="https://github.com/user-attachments/assets/cc19ccde-f8fa-40d5-8b4d-82215777dc6b" />
<img alt="image" src="https://github.com/user-attachments/assets/734ce6d0-6c66-49cf-a0f7-8236f7435be3" />
<img alt="image" src="https://github.com/user-attachments/assets/b6593321-1089-4f00-8011-5ef08cf80d88" />

`can you tell me which artifacts target the USN journal`
<img alt="image" src="https://github.com/user-attachments/assets/b9f93b1c-4a08-437d-b25a-ff82bdd2ab8c" />

