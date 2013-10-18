using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Thinktecture.IdentityModel.Authorization.WebApi;

namespace WebApiBook.Security.Facts.Authz
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;
    using System.Web.Http;
    using System.Web.Http.Controllers;
    using Xunit;

    public class ScopeExampleResourceController : ApiController
    {
        public HttpResponseMessage Get()
        {
            return new HttpResponseMessage
            {
                Content = new StringContent("resource representation")
            };
        }

        [Scope("create")]
        public HttpResponseMessage Post()
        {
            return new HttpResponseMessage()
            {
                Content = new StringContent("result representation")
            };
        }

        [Scope("delete")]
        public HttpResponseMessage Delete(string id)
        {
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    public class ScopeAttributeFacts
    {
        private HttpConfiguration _config;
        private HttpServer _server;
        private HttpClient _client;

        public ScopeAttributeFacts()
        {
            _config = new HttpConfiguration();
            _config.Routes.MapHttpRoute(
                "ApiDefault",
                "{controller}/{id}",
                new { Id = RouteParameter.Optional }
                );
            _server = new HttpServer(_config);
            _client = new HttpClient(_server);
        }

        [Fact]
        public async Task Anonymous_GET_are_allowed()
        {
            var res = await _client.GetAsync("https://www.example.net/scopeexampleresource");
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Anonymous_POST_are_not_allowed()
        {
            var res = await _client.PostAsync("https://www.example.net/scopeexampleresource", new StringContent(""));
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_POST_with_create_scope_are_allowed()
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "https://www.example.net/scopeexampleresource");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new ClaimsPrincipal(new []
                {
                    new ClaimsIdentity(new []{new Claim("scope","create"), }), 
                })
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_DELETE_with_delete_scope_are_allowed()
        {
            var req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/scopeexampleresource/123");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new ClaimsPrincipal(new[]
                {
                    new ClaimsIdentity(new []{new Claim("scope","create"), }), 
                })
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/scopeexampleresource/123");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new ClaimsPrincipal(new[]
                {
                    new ClaimsIdentity(new []
                    {
                        new Claim("scope","create"),
                        new Claim("scope","delete"), 
                    }), 
                })
            });
            res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);
        }
    }
}
