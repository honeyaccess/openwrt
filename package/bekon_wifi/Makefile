include $(TOPDIR)/rules.mk

# Name and release number of this package
PKG_NAME:=hotspot_beacon
PKG_RELEASE:=1

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/honeyaccess/nodogsplash.git
PKG_SOURCE_VERSION:=master
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
include $(INCLUDE_DIR)/package.mk

define Package/hotspot_beacon
	SECTION:=utils
	CATEGORY:=Utilities
  	DEPENDS:=+libpcap
	TITLE:=utility for sending Hotspot 2.0 beacons via given interface in promiscus mode
endef


define Package/hotspot_beacon/description
  Hotspot 2.0 Beacons
endef

define Package/hotspot_beacon/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/bin/
endef

$(eval $(call BuildPackage,hotspot_beacon))

