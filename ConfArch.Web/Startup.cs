using ConfArch.Data;
using ConfArch.Data.Repositories;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace ConfArch.Web
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews(o => o.Filters.Add(new AuthorizeFilter()));        //The Filter makes all Controllers needing Authentication by Default unless specified by AllowAnonymous.
            services.AddScoped<IConferenceRepository, ConferenceRepository>();
            services.AddScoped<IProposalRepository, ProposalRepository>();
            services.AddScoped<IAttendeeRepository, AttendeeRepository>();
            services.AddScoped<IUserRepository, UserRepository>();

            services.AddDbContext<ConfArchDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"), 
                    assembly => assembly.MigrationsAssembly(typeof(ConfArchDbContext).Assembly.FullName)));

            services.AddAuthentication( o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;                     //Note that the Default Authentication Scheme Name for Cookies is "Cookies" and for Google is "Google"
                //o.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;                         //Here we set the DefaultAuthentication Scheme to Cookies so the two Scheeme Actions of Authentication and Forbid will be of Cookies while the Scheme Action of Challenge (Login) will be Google Default Scheme i.e. Google redirected Login and not Cookie Login
            })                                                                                              //Commented out the above line so that Authentication can happen via local Login or Google Login          
            
                    .AddCookie()
                    .AddCookie(ExternalAuthenticationDefaults.AuthenticationScheme)
                    .AddGoogle(o =>                     //This Part is responsible for adding the Google Authentication using ClientId and ClientSecret of the Registered App.
                    {
                        o.SignInScheme = ExternalAuthenticationDefaults.AuthenticationScheme;
                        o.ClientId = Configuration["Google:ClientId"];
                        o.ClientSecret = Configuration["Google:ClientSecret"];

                    });     
                    //.AddCookie(o => o.LoginPath = "account/sigin");     //Incase the Login Path has to be changed from the default settings.
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();            //Order is Imp. Should be placed before Endpoints so that it is checked before Endpoints.
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Conference}/{action=Index}/{id?}");
            });
        }
    }
}
