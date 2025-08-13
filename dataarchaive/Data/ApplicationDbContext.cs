using dataarchaive.Models;
using Microsoft.EntityFrameworkCore;

namespace dataarchaive.Data
{
    public class ApplicationDbContext: DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
         public DbSet<Order> Orders { get; set; }
         public DbSet<ArchivedOrder> ArchivedOrders { get; set; }
    }
}
