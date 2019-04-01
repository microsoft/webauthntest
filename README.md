## Deploying a local instance
1. Download and install [the latest NodeJS](https://nodejs.org/en/) 
2. Download and install [VS Code](https://code.visualstudio.com/) 
3. Download and install [MongoDB Community](https://www.mongodb.com/download-center#community)
4. Clone this repository
5. Run npm install in the root directory
6. Open this repository in VS Code
7. Launch program - configurations should already be set

## Deploying to production
Things you need to deploy
- Create a app services web project
- Create a Cosmos DB with API mongodb

Before deploying, you'll need to define the following environment variables inside app services application settings so they can be accessed by this NODEJS app at runtime:
- MONGODB_URL - connection URL to your mongodb. Get it from cosmos db settings. Pick the latest Node.js 3.0 connection string under quick start.
- JWT_SECRET - some long random string
- HOSTNAME - hostname of your deployed service (e.g. "webauthntestapp.azurewebsites.net")
- ENFORCE_SSL_AZURE - set to "true"

## Contributing
This project welcomes contributions and suggestions. Most contributions require you to agree to a Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

## Code of Conduct
This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
