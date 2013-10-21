using System;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using Xunit;

namespace WebApiBook.Security.Facts.Authz
{
    [Authorize]
    public class ResourceController : ApiController
    {
        [AllowAnonymous]
        public HttpResponseMessage Get()
        {
            return new HttpResponseMessage
            {
                Content = new StringContent("resource representation")
            };
        }
        public HttpResponseMessage Post()
        {
            return new HttpResponseMessage()
            {
                Content = new StringContent("result representation")
            };
        }
        [Authorize(Roles = "ProjectManager")]
        public HttpResponseMessage Delete(string id)
        {
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    public class AuthorizeAttributeFacts
    {
        private HttpConfiguration _config;
        private HttpServer _server;
        private HttpClient _client;

        public AuthorizeAttributeFacts()
        {
            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity());
            _config = new HttpConfiguration();
            _config.Routes.MapHttpRoute(
                "ApiDefault",
                "{controller}/{id}",
                new {Id = RouteParameter.Optional}
                );
            _server = new HttpServer(_config);
            _client = new HttpClient(_server);
        }

        [Fact]
        public async Task Anonymous_GET_are_allowed()
        {
            var res = await _client.GetAsync("https://www.example.net/resource");
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Anonymous_POST_are_not_allowed()
        {
            var res = await _client.PostAsync("https://www.example.net/resource",new StringContent(""));
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_POST_are_allowed()
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "https://www.example.net/resource");
            req.SetRequestContext(new HttpRequestContext
            {
                Principal = new ClaimsPrincipal(new GenericIdentity("Alice"))
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_DELETE_are_allowed_for_ProjectManagers()
        {
            var req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/resource/123");
            req.SetRequestContext(new HttpRequestContext
            {
                Principal = new ClaimsPrincipal(new GenericIdentity("Alice"))
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/resource/123");
            req.SetRequestContext(new HttpRequestContext
            {
                Principal = new GenericPrincipal(new GenericIdentity("Alice"), new []{"ProjectManager"})
            });
            res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);
        }
    }
}
