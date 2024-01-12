using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;

namespace IdentityManagerServerApi.Data
{
    //public class AppDbContext(DbContextOptions options) : IdentityDbContext<ApplicationUser>(options)
    //{
    //}
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {

        public AppDbContext(DbContextOptions<AppDbContext> options)
    : base(options)
        {
        }

    }
}
