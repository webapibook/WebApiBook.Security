using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace WebApiBook.Security.Facts
{
    public class ClaimFacts
    {
        private Claim GetNameClaim()
        {
            AppDomain.CurrentDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            var identity = Thread.CurrentPrincipal.Identity as ClaimsIdentity;
            Assert.NotNull(identity);
            return identity.Claims.First(c => c.Type == ClaimsIdentity.DefaultNameClaimType);
        }

        [Fact]
        public void Claims_have_an_issuer_a_type_and_a_value()
        {
            var nameClaim = GetNameClaim();

            Assert.Equal("AD AUTHORITY", nameClaim.Issuer);
            Assert.Equal(ClaimTypes.Name, nameClaim.Type);
            Assert.Equal("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", nameClaim.Type);
            Assert.True(nameClaim.Value.EndsWith("pedro"));
        }

        [Fact]
        public void Claims_also_have_a_value_type()
        {
            var nameClaim = GetNameClaim();
            Assert.Equal(ClaimValueTypes.String, nameClaim.ValueType);
            Assert.Equal("http://www.w3.org/2001/XMLSchema#string", nameClaim.ValueType);
        }
    }
}
