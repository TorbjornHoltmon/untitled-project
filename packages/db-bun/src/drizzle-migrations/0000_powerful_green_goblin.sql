CREATE TABLE `cart` (
	`id` text PRIMARY KEY NOT NULL,
	`active` integer,
	`created_at` text,
	`updated_at` text
);
--> statement-breakpoint
CREATE TABLE `cart_item` (
	`id` text PRIMARY KEY NOT NULL,
	`sku_id` text NOT NULL,
	`cart_id` integer NOT NULL,
	`price_id` integer NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	FOREIGN KEY (`sku_id`) REFERENCES `variant`(`sku_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`cart_id`) REFERENCES `cart`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `category` (
	`id` text PRIMARY KEY NOT NULL,
	`title` text(256),
	`slug` text(256),
	`description` text,
	`parent_id` text,
	`created_at` text,
	`updated_at` text,
	FOREIGN KEY (`parent_id`) REFERENCES `category`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `order` (
	`id` text PRIMARY KEY NOT NULL,
	`cart_id` text NOT NULL,
	`items_at_time_of_order` text,
	`created_at` text,
	`updated_at` text,
	FOREIGN KEY (`cart_id`) REFERENCES `cart`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `order_item` (
	`id` text PRIMARY KEY NOT NULL,
	`sku_id` text NOT NULL,
	`order_id` text NOT NULL,
	`created_at` text,
	`updated_at` text,
	`price` integer,
	`base_price` integer,
	`tax_amount` integer,
	`discount_amount` integer,
	`total_amount` integer,
	FOREIGN KEY (`sku_id`) REFERENCES `variant`(`sku_id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`order_id`) REFERENCES `order`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `product` (
	`id` text PRIMARY KEY NOT NULL,
	`title` text(256),
	`created_at` text,
	`updated_at` text
);
--> statement-breakpoint
CREATE TABLE `product_category` (
	`product_id` text,
	`category_id` text,
	FOREIGN KEY (`product_id`) REFERENCES `product`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`category_id`) REFERENCES `category`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `variant` (
	`id` text PRIMARY KEY NOT NULL,
	`sku_id` text,
	`title` text,
	`price` integer,
	`created_at` text,
	`updated_at` text,
	`product_id` text,
	FOREIGN KEY (`product_id`) REFERENCES `product`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `cart_table_id_idx` ON `cart` (`id`);--> statement-breakpoint
CREATE INDEX `cart_table_created_at_idx` ON `cart` (`created_at`);--> statement-breakpoint
CREATE INDEX `cart_table_updated_at_idx` ON `cart` (`updated_at`);--> statement-breakpoint
CREATE INDEX `cart_item_table_id_idx` ON `cart_item` (`id`);--> statement-breakpoint
CREATE INDEX `cart_item_table_cart_id_idx` ON `cart_item` (`cart_id`);--> statement-breakpoint
CREATE INDEX `cart_item_table_sku_id_idx` ON `cart_item` (`sku_id`);--> statement-breakpoint
CREATE INDEX `cart_item_table_created_at_idx` ON `cart_item` (`created_at`);--> statement-breakpoint
CREATE INDEX `cart_item_table_updated_at_idx` ON `cart_item` (`updated_at`);--> statement-breakpoint
CREATE INDEX `category_table_id_idx` ON `category` (`id`);--> statement-breakpoint
CREATE INDEX `order_table_id_idx` ON `order` (`id`);--> statement-breakpoint
CREATE INDEX `order_item_table_id_idx` ON `order_item` (`id`);--> statement-breakpoint
CREATE INDEX `order_item_table_order_id_idx` ON `order_item` (`order_id`);--> statement-breakpoint
CREATE INDEX `order_item_table_sku_id_idx` ON `order_item` (`sku_id`);--> statement-breakpoint
CREATE INDEX `product_table_id_idx` ON `product` (`id`);--> statement-breakpoint
CREATE INDEX `product_table_created_at_idx` ON `product` (`created_at`);--> statement-breakpoint
CREATE INDEX `product_table_updated_at_idx` ON `product` (`updated_at`);--> statement-breakpoint
CREATE INDEX `product_category_table_product_id_idx` ON `product_category` (`product_id`);--> statement-breakpoint
CREATE INDEX `product_category_table_category_id_idx` ON `product_category` (`category_id`);--> statement-breakpoint
CREATE INDEX `variant_table_id_idx` ON `variant` (`id`);--> statement-breakpoint
CREATE INDEX `variant_table_sku_id_idx` ON `variant` (`sku_id`);--> statement-breakpoint
CREATE INDEX `variant_table_product_id_idx` ON `variant` (`product_id`);--> statement-breakpoint
CREATE INDEX `variant_table_created_at_idx` ON `variant` (`created_at`);--> statement-breakpoint
CREATE INDEX `variant_table_updated_at_idx` ON `variant` (`updated_at`);