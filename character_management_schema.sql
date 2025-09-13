-- Character Management Schema Enhancement for JX2 Paysys
-- Based on JX1 Paysys analysis and PCAP packet structure analysis
-- Run this after the main jx2_paysys.sql to add character management support

USE paysys;

-- Characters table for character management (based on JX1 analysis)
CREATE TABLE IF NOT EXISTS `characters` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(32) NOT NULL COMMENT 'Character name (unique across server)',
  `username` varchar(32) NOT NULL COMMENT 'Account owner username',
  `level` int(11) NOT NULL DEFAULT 1 COMMENT 'Character level',
  `class` int(11) NOT NULL DEFAULT 0 COMMENT 'Character class (0-10)',
  `gender` int(1) NOT NULL DEFAULT 0 COMMENT 'Character gender (0=male, 1=female)',
  `map_id` int(11) NOT NULL DEFAULT 1 COMMENT 'Current map ID',
  `x` int(11) NOT NULL DEFAULT 100 COMMENT 'X coordinate', 
  `y` int(11) NOT NULL DEFAULT 100 COMMENT 'Y coordinate',
  `created` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'Character creation time',
  `last_login` datetime NULL COMMENT 'Last login time',
  `experience` bigint(20) NOT NULL DEFAULT 0 COMMENT 'Experience points',
  `money` int(11) NOT NULL DEFAULT 0 COMMENT 'Character money',
  `stats_str` int(11) NOT NULL DEFAULT 10 COMMENT 'Strength stat',
  `stats_agi` int(11) NOT NULL DEFAULT 10 COMMENT 'Agility stat', 
  `stats_int` int(11) NOT NULL DEFAULT 10 COMMENT 'Intelligence stat',
  `stats_vit` int(11) NOT NULL DEFAULT 10 COMMENT 'Vitality stat',
  `hp` int(11) NOT NULL DEFAULT 100 COMMENT 'Current HP',
  `max_hp` int(11) NOT NULL DEFAULT 100 COMMENT 'Maximum HP',
  `mp` int(11) NOT NULL DEFAULT 50 COMMENT 'Current MP',
  `max_mp` int(11) NOT NULL DEFAULT 50 COMMENT 'Maximum MP',
  `skill_points` int(11) NOT NULL DEFAULT 0 COMMENT 'Skill points available',
  `status_flags` int(11) NOT NULL DEFAULT 0 COMMENT 'Character status flags',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_name` (`name`),
  KEY `idx_username` (`username`),
  KEY `idx_level` (`level`),
  CONSTRAINT `fk_characters_account` FOREIGN KEY (`username`) REFERENCES `account` (`username`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Character data table based on JX1 analysis';

-- Character inventory table (for future extension)
CREATE TABLE IF NOT EXISTS `character_inventory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `character_id` int(11) NOT NULL,
  `slot_id` int(11) NOT NULL COMMENT 'Inventory slot position',
  `item_id` int(11) NOT NULL COMMENT 'Item template ID',
  `quantity` int(11) NOT NULL DEFAULT 1 COMMENT 'Item stack quantity',
  `durability` int(11) NOT NULL DEFAULT 100 COMMENT 'Item durability',
  `enchant_level` int(11) NOT NULL DEFAULT 0 COMMENT 'Item enchantment level',
  `item_data` text COMMENT 'Serialized item data (JSON)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_char_slot` (`character_id`, `slot_id`),
  KEY `idx_character` (`character_id`),
  CONSTRAINT `fk_inventory_character` FOREIGN KEY (`character_id`) REFERENCES `characters` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Character inventory system';

-- Character skills table (for future extension)
CREATE TABLE IF NOT EXISTS `character_skills` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `character_id` int(11) NOT NULL,
  `skill_id` int(11) NOT NULL COMMENT 'Skill template ID',
  `skill_level` int(11) NOT NULL DEFAULT 1 COMMENT 'Current skill level',
  `experience` int(11) NOT NULL DEFAULT 0 COMMENT 'Skill experience points',
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_char_skill` (`character_id`, `skill_id`),
  KEY `idx_character` (`character_id`),
  CONSTRAINT `fk_skills_character` FOREIGN KEY (`character_id`) REFERENCES `characters` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='Character skills system';

-- Insert test characters for development
INSERT INTO `characters` (`name`, `username`, `level`, `class`, `gender`, `map_id`, `x`, `y`) VALUES
('TestChar1', 'admin', 10, 1, 0, 1, 150, 150),
('TestChar2', 'admin', 5, 2, 1, 1, 200, 200),
('AdminChar', 'admin', 99, 0, 0, 1, 100, 100)
ON DUPLICATE KEY UPDATE name=name;

-- Update table_names registry
INSERT INTO `table_names` (`TABLE_NAME`) VALUES 
('characters'),
('character_inventory'), 
('character_skills')
ON DUPLICATE KEY UPDATE TABLE_NAME=TABLE_NAME;

-- Add character management variables
INSERT INTO `variables` (`Variable_name`, `VARIABLE_VALUE`) VALUES
('max_characters_per_account', '8'),
('character_name_min_length', '2'),
('character_name_max_length', '32'),
('default_character_level', '1'),
('default_character_map', '1'),
('default_character_x', '100'),
('default_character_y', '100')
ON DUPLICATE KEY UPDATE Variable_name=Variable_name;

COMMIT;