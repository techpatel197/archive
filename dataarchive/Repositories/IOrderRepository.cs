using dataarchaive.Models;

namespace dataarchaive.Repositories
{
    public interface IOrderRepository
    {
        Task<List<Order>> GetActiveOrdersAsync();
        Task<List<ArchivedOrder>> GetArchivedOrdersAsync();
        Task AddOrderAsync(Order order);
        Task ArchiveOrdersAsync(List<int> orderIds);
    }
}
