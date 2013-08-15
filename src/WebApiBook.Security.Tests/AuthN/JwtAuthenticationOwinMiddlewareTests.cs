using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using WebApiBook.Security.AuthN;
using Xunit;

namespace WebApiBook.Security.Tests.AuthN
{
    public class JwtAuthenticationOwinMiddlewareTests
    {
        public const string Key =
            "VGhlIE1hZ2ljIFdvcmRzIGFyZSBTcXVlYW1pc2ggT3NzaWZyYWdlIFRoZSBNYWdpYyBXb3JkcyBhcmUgU3F1ZWFtaXNoIE9zc2lmcmFnZQ==";
        public const string Issuer = "http://issuer.webapibook.net";
        private const int LifetimeInMinutes = 5;
        private const string Audience = "http://example.net";

        private JwtAuthenticationOptions Options = new JwtAuthenticationOptions
        {
            Realm = "webapibook",
            NameClaimType = ClaimTypes.NameIdentifier,
        }.WithIssuer("http://issuer.webapibook.net")
         .WithKey(Key);

        private readonly string _tokenString;

        public JwtAuthenticationOwinMiddlewareTests()
        {
            var signingCredentials = new SigningCredentials(
                new InMemorySymmetricSecurityKey(Convert.FromBase64String(Key)),
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256");

            var now = DateTime.UtcNow;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new []
                        {
                            new Claim("sub", "Alice"),
                            new Claim("email", "alice@webapibook.net"), 
                        }),
                TokenIssuerName = Issuer,
                AppliesToAddress = Audience,
                Lifetime = new Lifetime(now, now.AddMinutes(LifetimeInMinutes)),
                SigningCredentials = signingCredentials,
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            _tokenString = tokenHandler.WriteToken(token);
        }
        

        [Fact]
        public async Task Correctly_authenticated_request_has_a_valid_User()
        {
            await OwinTester.Run(
               useConfiguration: app =>
               {
                   app.UseJwtAuthentication(Options);
               },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("bearer", _tokenString);
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
                   app.UseJwtAuthentication(Options);
               },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("bearer", _tokenString);
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
                    app.UseJwtAuthentication(Options);
                },
                useRequest: () =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, "http://example.net");
                    req.Headers.Authorization = new AuthenticationHeaderValue("bearer", _tokenString + "x");
                    return req;
                },
                assertRequest: ctx =>
                {
                    ctx.Response.StatusCode = ctx.Request.User == null || !ctx.Request.User.Identity.IsAuthenticated ? 401 : 200;
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
                    app.UseJwtAuthentication(Options);
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
                    Assert.Equal("Bearer", response.Headers.WwwAuthenticate.First().Scheme);
                    Assert.Equal("realm=webapibook", response.Headers.WwwAuthenticate.First().Parameter);
                }
           );
        }
    }
}
