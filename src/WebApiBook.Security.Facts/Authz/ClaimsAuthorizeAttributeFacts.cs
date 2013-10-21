using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Principal;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Controllers;
using Thinktecture.IdentityModel.Authorization;
using Thinktecture.IdentityModel.Authorization.WebApi;
using Thinktecture.IdentityModel.Constants;
using Xunit;

namespace WebApiBook.Security.Facts
{
    public class ClaimsResourceController : ApiController
    {
 
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
 
        public HttpResponseMessage Delete(string id)
        {
            return new HttpResponseMessage(HttpStatusCode.NoContent);
        }
    }

    public class CustomPolicyClaimsAuthorizationManager : ClaimsAuthorizationManager
    {
        public override bool CheckAccess(AuthorizationContext context)
        {
            var subject = context.Principal;
            var method = context.Action.First(c => c.Type == ClaimsAuthorization.ActionType).Value;
            var controller = context.Resource.First(c => c.Type == ClaimsAuthorization.ResourceType).Value;

            if (controller == "ClaimsResource")
            {
                if (method.Equals("GET", StringComparison.OrdinalIgnoreCase))
                    return true;

                if (method.Equals("DELETE", StringComparison.OrdinalIgnoreCase) && !subject.IsInRole("ProjectManager"))
                    return false;

                return subject.Identity.IsAuthenticated;
            }
            return false;
        }
    }

    public class SelfHostHttpRequestContext : HttpRequestContext
    {
        public override IPrincipal Principal {
            get
            {
                return Thread.CurrentPrincipal;
            }

            set
            {
                Thread.CurrentPrincipal = value;
            } 
       }
    }

    public class ClaimsAuthorizeAttributeFacts
    {
        private HttpConfiguration _config;
        private HttpServer _server;
        private HttpClient _client;

        public ClaimsAuthorizeAttributeFacts()
        {
            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity());
            _config = new HttpConfiguration();
            _config.Routes.MapHttpRoute(
                "ApiDefault",
                "{controller}/{id}",
                new { Id = RouteParameter.Optional }
                );
            _config.Filters.Add(new ClaimsAuthorizeAttribute());
            FederatedAuthentication.FederationConfiguration.IdentityConfiguration.ClaimsAuthorizationManager = new CustomPolicyClaimsAuthorizationManager();
            _server = new HttpServer(_config);
            _client = new HttpClient(_server);
        }

        [Fact]
        public async Task Anonymous_GET_are_allowed()
        {
            var res = await _client.GetAsync("https://www.example.net/claimsresource");
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Anonymous_POST_are_not_allowed()
        {
            var res = await _client.PostAsync("https://www.example.net/claimsresource", new StringContent(""));
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_POST_are_allowed()
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "https://www.example.net/claimsresource");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new ClaimsPrincipal(new GenericIdentity("Alice"))
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        }

        [Fact]
        public async Task Authenticated_DELETE_are_allowed_for_ProjectManagers()
        {
            var req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/claimsresource/123");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new ClaimsPrincipal(new GenericIdentity("Alice"))
            });
            var res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);

            req = new HttpRequestMessage(HttpMethod.Delete, "https://www.example.net/claimsresource/123");
            req.SetRequestContext(new SelfHostHttpRequestContext
            {
                Principal = new GenericPrincipal(new GenericIdentity("Alice"), new[] { "ProjectManager" })
            });
            res = await _client.SendAsync(req);
            Assert.Equal(HttpStatusCode.NoContent, res.StatusCode);
        }
    }
    
}
