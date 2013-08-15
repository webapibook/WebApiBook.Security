using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace WebApiBook.Security.Facts
{
    public class JwtFacts
    {
        private static byte[] GetRandomBytes(int len)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                var key = new byte[256];
                rng.GetBytes(key);
                return key;
            }
        }

        [Fact]
        public void Can_create_and_consume_jwt_tokens()
        {
            const string issuer = "http://issuer.webapibook.net";
            const string audience = "http://example.net";
            const int lifetimeInMinutes = 5;

            var tokenHandler = new JwtSecurityTokenHandler();

            var symmetricKey = GetRandomBytes(256 / 8);
            var signingCredentials = new SigningCredentials(
                new InMemorySymmetricSecurityKey(symmetricKey),
                "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                "http://www.w3.org/2001/04/xmlenc#sha256");

            var now = DateTime.UtcNow;

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new []
                        {
                            new Claim("sub", "alice@webapibook.net"),
                            new Claim("email", "alice@webapibook.net"), 
                            new Claim("name", "Alice"), 
                        }),
                TokenIssuerName = issuer,
                AppliesToAddress = audience,
                Lifetime = new Lifetime(now, now.AddMinutes(lifetimeInMinutes)),
                SigningCredentials = signingCredentials,
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            var parts = tokenString.Split('.');
            Assert.Equal(3, parts.Length);

            var validationParameters = new TokenValidationParameters()
            {
                AllowedAudience = audience,
                SigningToken = new BinarySecretSecurityToken(symmetricKey),
                ValidIssuer = issuer,
            };

            tokenHandler.NameClaimType = ClaimTypes.NameIdentifier;
            var principal = tokenHandler.ValidateToken(tokenString, validationParameters);

            var identity = principal.Identities.First();

            Assert.Equal("alice@webapibook.net", identity.Name);
            Assert.Equal("alice@webapibook.net", identity.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value);
            Assert.Equal("alice@webapibook.net", identity.Claims.First(c => c.Type == ClaimTypes.Email).Value);
            Assert.Equal("Alice", identity.Claims.First(c => c.Type == "name").Value);
            Assert.Equal(issuer, identity.Claims.First().Issuer);
        }
    }
}
