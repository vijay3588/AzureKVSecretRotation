// Default URL for triggering event grid function in the local environment.
// http://localhost:7071/runtime/webhooks/EventGrid?functionName={functionname}
using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.Azure.EventGrid.Models;
using Microsoft.Azure.WebJobs.Extensions.EventGrid;
using Microsoft.Extensions.Logging;
using System.Text.RegularExpressions;
using Azure.Security.KeyVault.Secrets;
using Azure.Identity;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;

namespace AzureKVRotationConnVehicle
{
    public static class KVSecretrotation
    {

        [FunctionName("KVSecretrotation")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "AZFW0001:Invalid binding attributes", Justification = "<Pending>")]
        public static void Run([EventGridTrigger] EventGridEvent eventGridEvent, ILogger log)
        {
            log.LogInformation("C# Event trigger function processed a request.");
            var secretName = eventGridEvent.Subject;
            var secretVersion = Regex.Match(eventGridEvent.Data.ToString(), "Version\":\"([a-z0-9]*)").Groups[1].ToString();
            var keyVaultName = Regex.Match(eventGridEvent.Topic, ".vaults.(.*)").Groups[1].ToString();
            log.LogInformation($"Key Vault Name: {keyVaultName}");
            log.LogInformation($"Secret Name: {secretName}");
            log.LogInformation($"Secret Version: {secretVersion}");

            //instaed of this directlly use the code below
            //SecretRotator.RotateSecret(log, secretName, keyVaultName);
            //Retrieve Current Secret
            var kvUri = "https://" + keyVaultName + ".vault.azure.net";
            var client = new SecretClient(new Uri(kvUri), new DefaultAzureCredential());
            KeyVaultSecret secret = client.GetSecret(secretName);
            log.LogInformation("Secret Info Retrieved");

            //Retrieve Secret Info
            var appId = secret.Properties.Tags.ContainsKey("appid") ? secret.Properties.Tags["appid"] : "";

            UpdateSecretAttributes(kvUri + "/secrets"+ secretName ).GetAwaiter().GetResult();

        }

        private static async Task<string> GetAccessTokenAsync(string authority, string resource, string scope)
        {
            string clientId = "770e59ee-a1c0-4b52-970e-863a32889225";
            string clientSecret = "dkF8Q~NOINg5018C8L7So.CGclTXyxkGaQmzadus";
            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(clientId, clientSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }

        public static async Task<string> GetSecretFromVault(string secretKeyIdentifier)
        {
            var client = new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(GetAccessTokenAsync),
                new System.Net.Http.HttpClient());

            var secret = await client.GetSecretAsync(secretKeyIdentifier).ConfigureAwait(false);

            return secret.Value;
        }

        public static async Task<string> UpdateSecretAttributes(string secretKeyIdentifier)
        {
            var client = new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(GetAccessTokenAsync),
                new System.Net.Http.HttpClient());

            SecretAttributes attributes = new SecretAttributes();
            attributes.Expires = DateTime.UtcNow.AddDays(180);

            var secret = await client.UpdateSecretAsync(secretKeyIdentifier, null, attributes, null).ConfigureAwait(false);

            return secret.Value;
        }
    }
}
