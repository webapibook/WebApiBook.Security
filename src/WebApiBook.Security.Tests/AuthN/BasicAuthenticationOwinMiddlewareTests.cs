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
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Owin;
using WebApiBook.Security.AuthN;
using Xunit;
using Xunit.Sdk;

namespace WebApiBook.Security.Tests.AuthN
{

    public static class OwinTester
    {
        public async static Task Run(
            Action<IAppBuilder> useConfiguration,
            Func<HttpRequestMessage> useRequest,
            Action<IOwinContext> assertRequest,
            Action<HttpResponseMessage> assertResponse)
        {
            var server = new TestServer();
            server.Open(app =>
            {
                useConfiguration(app);
                app.Use((ctx, next) =>
                {
                    assertRequest(ctx);
                    return Task.FromResult<object>(null);
                });
            });
            var request = useRequest();
            var response = await server.HttpClient.SendAsync(request);
            assertResponse(response);
        }
    }

    public class BasicAuthenticationOwinMiddlewareTests
    {
        private BasicAuthenticationOptions Options = new BasicAuthenticationOptions
        {
            ValidateCredentials = (un, pw) =>
            {
                var t = un != pw
                    ? null
                    : new AuthenticationTicket
                        (
                        new ClaimsIdentity(new GenericIdentity(un)),
                        new AuthenticationProperties()
                        );

                return Task.FromResult(t);
            },
            Realm = "webapibook"
        };

       
        [Fact]
        public async Task Correctly_authenticated_request_has_a_valid_User()
        {
            await OwinTester.Run(
               useConfiguration: app =>
               {
                   app.UseBasicAuthentication(Options);
               },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:Alice")));
                    return req;
                },
               assertRequest: ctx =>
               {
                   Assert.Equal("Alice", ctx.Request.User.Identity.Name);
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
            await OwinTester.Run(
               useConfiguration: app =>
               {
                   app.UseBasicAuthentication(Options);
               },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:Alice")));
                    return req;
                },
                assertRequest: ctx =>
                {
                    Assert.Equal("Alice", ctx.Request.User.Identity.Name);
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
            await OwinTester.Run(
                useConfiguration: app =>
                {
                    app.UseBasicAuthentication(Options);
                },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                        Convert.ToBase64String(
                        Encoding.ASCII.GetBytes("Alice:NotAlice")));
                    return req;
                },
                assertRequest: ctx =>
                {
                    Assert.False(true, "should not reach next middleware");
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
            await OwinTester.Run(
                useConfiguration: app =>
                {
                    app.UseBasicAuthentication(Options);
                },
                useRequest: () =>
                {
                    return new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                },
                 assertRequest: ctx =>
                {
                    Assert.Null(ctx.Request.User);
                    ctx.Response.StatusCode = 401;
                },
                
                assertResponse: response =>
                {
                    Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                    Assert.Equal("Basic", response.Headers.WwwAuthenticate.First().Scheme);
                    Assert.Equal("realm=webapibook", response.Headers.WwwAuthenticate.First().Parameter);
                }
           );
        }

        [Fact]
        public async Task Supports_UTF8_usernames_and_password()
        {
            await OwinTester.Run(
                 useConfiguration: app =>
                 {
                     app.UseBasicAuthentication(Options);
                 },
                 useRequest: () =>
                 {
                     var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                     req.Headers.Authorization = new AuthenticationHeaderValue("basic",
                         Convert.ToBase64String(
                         Encoding.UTF8.GetBytes("Alíç€:Alíç€")));
                     return req;
                 },
                  assertRequest: ctx =>
                  {
                      Assert.Equal("Alíç€", ctx.Request.User.Identity.Name);
                  },
                 assertResponse: response =>
                 {
                     Assert.Equal(HttpStatusCode.OK, response.StatusCode);
                 }
            );
        }

    }
}
