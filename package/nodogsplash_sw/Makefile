#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=nodogsplash_sw
PKG_FIXUP:=autoreconf
PKG_VERSION:=sw_6
PKG_RELEASE:=6

PKG_SOURCE_PROTO:=git
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)/
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/honeyaccess/nodogsplash.git
PKG_SOURCE_VERSION:=development_apple_share
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_BUILD_PARALLEL:=1
PKG_LICENSE:=GPL-2.0+

include $(INCLUDE_DIR)/package.mk


define Package/nodogsplash_sw
	SECTION:=utils
	CATEGORY:=Utilities
	DEPENDS:=+libpthread +iptables-mod-ipopt
	TITLE:=Open public network gateway daemon
	URL:=https://github.com/honeyaccess/nodogsplash
endef

define Package/nodogsplash_sw/description
	Custom nodogsplash build.
endef

define Package/nodogsplash_sw/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nodogsplash $(1)/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ndsctl $(1)/bin/

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) files/nodogsplash.init $(1)/etc/init.d/nodogsplash
endef

$(eval $(call BuildPackage,nodogsplash_sw))
