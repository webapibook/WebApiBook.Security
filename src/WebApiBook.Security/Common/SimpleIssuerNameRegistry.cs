using System.IdentityModel.Tokens;
using System.Linq;
using System.Text;

namespace WebApiBook.Security.Common
{
    public class SimpleIssuerNameRegistry : IssuerNameRegistry
    {
        public override string GetIssuerName(SecurityToken securityToken)
        {
            var x509Token = securityToken as X509SecurityToken;
            return x509Token == null ? null : x509Token.Certificate.SubjectName.Name;
        }
    }
}
