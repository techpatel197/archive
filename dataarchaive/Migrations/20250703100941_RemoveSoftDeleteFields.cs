using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace dataarchaive.Migrations
{
    /// <inheritdoc />
    public partial class RemoveSoftDeleteFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ArchivedDate",
                table: "Orders");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "ArchivedDate",
                table: "Orders",
                type: "datetime2",
                nullable: true);
        }
    }
}
