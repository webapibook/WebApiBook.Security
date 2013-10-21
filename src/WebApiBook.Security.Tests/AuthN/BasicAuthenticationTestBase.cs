using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using WebApiBook.Security.AuthN;
using WebApiBook.Security.Tests.Utils;
using Xunit;

namespace WebApiBook.Security.Tests.AuthN
{
    public abstract class BasicAuthenticationTestBase
    {
        protected readonly Action<HttpConfiguration> Config;

        public static Func<string, string, Task<ClaimsPrincipal>> TestValidator = (username, password) =>
        {
            var princ = username == password ? new ClaimsPrincipal(new GenericIdentity(username)) : null;
            return Task.FromResult(princ);
        };

        protected BasicAuthenticationTestBase(Action<HttpConfiguration> config)
        {
            Thread.CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity());
            Config = config;
        }

        [Fact]
        public async Task Correctly_authenticated_request_has_a_valid_User()
        {
            await Tester.Run(
                withConfiguration: configuration =>
                {
                    Config(configuration);
                },
                withRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:Alice")));
                    return req;
                },
                assertInAction: controller =>
                {
                    Assert.Equal("Alice", controller.User.Identity.Name);
                    return new HttpResponseMessage();
                },
                assertResponse: response =>
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                }
           );
        }

        [Fact]
        public async Task Correctly_authenticated_request_does_not_return_a_challenge()
        {
            await Tester.Run(
                withConfiguration: configuration =>
                {
                    Config(configuration);
                },
                withRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:Alice")));
                    return req;
                },
                assertInAction: controller =>
                {
                    Assert.Equal("Alice", controller.User.Identity.Name);
                    return new HttpResponseMessage();
                },
                assertResponse: response =>
                {
                    Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                    Assert.Equal(0, response.Headers.WwwAuthenticate.Count);
                }
           );
        }

        [Fact]
        public async Task Incorrectly_authenticated_request_returns_a_401_with_only_one_challenge()
        {
            await Tester.Run(
                withConfiguration: configuration =>
                {
                    Config(configuration);
                },
                withRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:NotAlice")));
                    return req;
                },
                assertInAction: controller =>
                {
                    Assert.False(true, "should not reach controller");
                    return new HttpResponseMessage();
                },
                assertResponse: response =>
                {
                    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                    Assert.Equal(1, response.Headers.WwwAuthenticate.Count);
                }
           );
        }


        [Fact]
        public async Task Non_authenticated_request_reaches_controller_with_an_unauthenticated_user()
        {
            await Tester.Run(
                withConfiguration: configuration =>
                {
                    Config(configuration);
                },
                withRequest: () =>
                {
                    return new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                },
                assertInAction: controller =>
                {
                    Assert.False(controller.User.Identity.IsAuthenticated);
                    return new HttpResponseMessage(HttpStatusCode.Unauthorized);
                },
                assertResponse: response =>
                {
                    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                    Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
                    Assert.Equal("realm=myrealm", response.Headers.WwwAuthenticate.First().Parameter);
                }
           );
        }

        [Fact]
        public async Task Supports_UTF8_usernames_and_password()
        {
            await Tester.Run(
                 withConfiguration: configuration =>
                 {
                     Config(configuration);
                 },
                 withRequest: () =>
                 {
                     var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                     req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                         Convert.ToBase64String(
                         Encoding.UTF8.GetBytes("Alíç€:Alíç€")));
                     return req;
                 },
                 assertInAction: controller =>
                 {
                     Assert.Equal("Alíç€", controller.User.Identity.Name);
                     return new HttpResponseMessage();
                 },
                 assertResponse: response =>
                 {
                     Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                 }
            );
        }
    }
}
