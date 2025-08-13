using dataarchaive.Models;

namespace dataarchaive.Repositories
{
    public class OrderService : IOrderService
    {
        private readonly IOrderRepository _orderRepository;

        public OrderService(IOrderRepository orderRepository)
        {
            _orderRepository = orderRepository;
        }

        public async Task<List<Order>> GetActiveOrdersAsync()
        {
            return await _orderRepository.GetActiveOrdersAsync();
        }

        public async Task<List<ArchivedOrder>> GetArchivedOrdersAsync()
        {
            return await _orderRepository.GetArchivedOrdersAsync();
        }

        public async Task AddOrderAsync(string orderNo, string orderName)
        {
            var order = new Order
            {
                OrderNo = orderNo,
                OrderName = orderName,
                IsArchived = false
            };
            await _orderRepository.AddOrderAsync(order);
        }

        public async Task ArchiveOrdersAsync(List<int> orderIds)
        {
            await _orderRepository.ArchiveOrdersAsync(orderIds);
        }
    }
}
