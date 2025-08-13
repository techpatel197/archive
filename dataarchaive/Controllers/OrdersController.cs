using dataarchaive.Models;
using dataarchaive.Repositories;
using dataarchaive.ViewModels;
using Microsoft.AspNetCore.Mvc;

namespace dataarchaive.Controllers
{
    public class OrdersController : Controller
    {
        private readonly IOrderService _orderService;

        public OrdersController(IOrderService orderService)
        {
            _orderService = orderService;
        }

        public async Task<IActionResult> Index()
        {
            var activeOrders = await _orderService.GetActiveOrdersAsync();
            var archivedOrders = await _orderService.GetArchivedOrdersAsync();

            var viewModel = new OrdersViewModel
            {
                ActiveOrders = activeOrders,
                ArchivedOrders = archivedOrders
            };

            return View(viewModel);
        }

        [HttpPost]
        public async Task<IActionResult> AddOrder(string orderNo, string orderName)
        {
            if (string.IsNullOrWhiteSpace(orderNo) || string.IsNullOrWhiteSpace(orderName))
            {
                return BadRequest("Order number and name are required");
            }

            var order = new Order
            {
                OrderNo = orderNo,
                OrderName = orderName
            };

            await _orderService.AddOrderAsync(orderNo,orderName);
            return RedirectToAction("Index");
        }

        [HttpPost]
        public async Task<IActionResult> ArchiveOrders([FromBody] List<int> orderIds)
        {
            if (orderIds == null || orderIds.Count == 0)
            {
                return BadRequest("No orders selected");
            }

            await _orderService.ArchiveOrdersAsync(orderIds);
            return Ok(new { success = true, message = "Orders archived successfully" });
        }
    }
}
