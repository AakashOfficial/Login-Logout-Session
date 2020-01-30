using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Login_Logout_Session.Startup))]
namespace Login_Logout_Session
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
