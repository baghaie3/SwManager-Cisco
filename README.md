Network Switch Management & Backup System
English
Overview
This project is a Flask-based web application for managing network switches and automating common network administration tasks.

It provides a centralized interface for storing device credentials, managing switches, collecting configuration backups, and performing operational tasks such as MAC address scanning and port‑security management.

The system is designed to help network administrators automate repetitive tasks, maintain configuration backups, and monitor network devices efficiently.

Main Features
Switch Management

Register and manage network switches
Organize devices by location
Associate credential profiles with devices
Credential Profiles

Secure storage of SSH and SNMP credentials
Encryption of sensitive data such as passwords and secrets
Configuration Backup

Automated retrieval of running-config from switches
Backup storage and logging
Export backups to SMB file servers
MAC Address Search

Scan switches for MAC addresses
Track MAC address location across ports
Store MAC activity history in the database
Port Security Management

View port-security information
Remove sticky MAC entries from interfaces
SMB Integration

Upload configuration backups to SMB shares
Session-based SMB authentication
Logging & Monitoring

System and device operation logs
Tracking of jobs and operations
User Authentication

Login system for administrators
Session-based authentication
Technology Stack
Python
Flask
SQLAlchemy
APScheduler
Netmiko (for network device communication)
SMB (pysmb)
HTML / Jinja Templates
Use Cases
This tool is useful for:

Network administrators managing multiple switches
Automating configuration backups
Locating MAC addresses in large networks
Managing port security entries
Maintaining centralized logs of network operations
فارسی
معرفی پروژه
این پروژه یک اپلیکیشن تحت وب مبتنی بر Flask برای مدیریت سوئیچ‌های شبکه و خودکارسازی کارهای مدیریتی شبکه است.

این سیستم به مدیران شبکه کمک می‌کند تا اطلاعات دسترسی دستگاه‌ها را مدیریت کنند، از کانفیگ سوئیچ‌ها بکاپ بگیرند، آدرس‌های MAC را جستجو کنند و وضعیت امنیت پورت‌ها را بررسی کنند.

هدف این پروژه ایجاد یک پنل متمرکز برای مدیریت تجهیزات شبکه و ساده‌سازی عملیات روزمره ادمین‌های شبکه است.

قابلیت‌های اصلی
مدیریت سوئیچ‌ها

ثبت و مدیریت سوئیچ‌های شبکه
دسته‌بندی دستگاه‌ها بر اساس موقعیت (Location)
اتصال Credential Profile به هر سوئیچ
مدیریت اطلاعات دسترسی

ذخیره امن اطلاعات ورود (SSH و SNMP)
رمزنگاری اطلاعات حساس مانند password و secret
گرفتن بکاپ از کانفیگ

دریافت خودکار running-config از سوئیچ‌ها
ذخیره و ثبت بکاپ‌ها
امکان انتقال بکاپ‌ها به سرورهای SMB
جستجوی MAC Address

اسکن سوئیچ‌ها برای یافتن MAC Address
نمایش محل اتصال MAC روی پورت‌ها
ذخیره تاریخچه مشاهده MAC در دیتابیس
مدیریت Port Security

مشاهده وضعیت port-security
حذف MACهای sticky از روی اینترفیس‌ها
اتصال به SMB

آپلود بکاپ‌ها روی SMB Share
مدیریت نشست (Session) برای اتصال SMB
سیستم لاگ

ثبت رویدادهای سیستم
ذخیره عملیات انجام شده روی دستگاه‌ها
احراز هویت کاربران

سیستم ورود کاربران
مدیریت نشست کاربران
تکنولوژی‌های استفاده شده
Python
Flask
SQLAlchemy
APScheduler
Netmiko
SMB (pysmb)
HTML / Jinja
کاربردها
این ابزار برای موارد زیر مناسب است:

مدیریت چندین سوئیچ در یک شبکه
گرفتن بکاپ منظم از تنظیمات دستگاه‌ها
پیدا کردن محل اتصال MAC Address در شبکه
مدیریت port-security
ثبت و بررسی لاگ عملیات شبکه
:::
