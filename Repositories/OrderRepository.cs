using dataarchaive.Data;
using dataarchaive.Models;
using Microsoft.EntityFrameworkCore;

namespace dataarchaive.Repositories
{
    public class OrderRepository : IOrderRepository
    {
        private readonly ApplicationDbContext _context;

        public OrderRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<List<Order>> GetActiveOrdersAsync()
        {
            return await _context.Orders.Where(o => !o.IsArchived).ToListAsync();
        }

        public async Task<List<ArchivedOrder>> GetArchivedOrdersAsync()
        {
            return await _context.ArchivedOrders.OrderByDescending(a => a.ArchivedDate).ToListAsync();
        }

        public async Task AddOrderAsync(Order order)
        {
            _context.Orders.Add(order);
            await _context.SaveChangesAsync();
        }

        // Repositories/OrderRepository.cs
        public async Task ArchiveOrdersAsync(List<int> orderIds)
        {
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var ordersToArchive = await _context.Orders
                    .Where(o => orderIds.Contains(o.Id))
                    .ToListAsync();

                if (!ordersToArchive.Any()) return;

                var archivedOrders = ordersToArchive.Select(o => new ArchivedOrder
                {
                    OrderNo = o.OrderNo,
                    OrderName = o.OrderName,
                    ArchivedDate = DateTime.Now
                }).ToList();

                await _context.ArchivedOrders.AddRangeAsync(archivedOrders);
                _context.Orders.RemoveRange(ordersToArchive);

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch
            {
                await transaction.RollbackAsync();
                throw;
            }
        }
    }
}
