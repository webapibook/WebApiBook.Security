using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;

namespace WebApiBook.Security.ResourceServer1
{
    class Client
    {
        private const string ClientId = "client1";
        private const string ClientSecret = "lEVsQppan6Jzv3gl0bViCB9PDKdLMUw6FxoEOzSwe8c";
        public async static Task Run()
        {
            var client = new HttpClient();
            var req = new HttpRequestMessage(HttpMethod.Post, "https://authzserver.example/resourceserver.example/oauth/token")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "scope1"}
                })
            };
            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", 
                Convert.ToBase64String(Encoding.ASCII.GetBytes(ClientId + ":" + ClientSecret)));
            var res = await client.SendAsync(req);
            res.EnsureSuccessStatusCode();
            var tokenRes = await res.Content.ReadAsAsync<AuthorizationResponse>();
            Console.WriteLine("access_token is {0}",tokenRes.access_token);

            req = new HttpRequestMessage(HttpMethod.Get, "http://resourceserver.example:8000/api/resource");
            req.Headers.Authorization = new AuthenticationHeaderValue("bearer", tokenRes.access_token);
            res = await client.SendAsync(req);
            var body = await res.Content.ReadAsStringAsync();
            Console.WriteLine(body);
        }
    }

    class AuthorizationResponse
    {
        public string access_token { get; set; }
    }
}
