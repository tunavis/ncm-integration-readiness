from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.deps import current_user, require_permission
from app.core.crypto import encrypt_secret
from app.models.device import Device
from app.models.backup import Backup
from app.models.schedule import BackupSchedule
from app.services.scheduler import remove_device_schedule
from app.schemas.device import DeviceCreate, DeviceUpdate, DeviceOut
from app.services.network import test_connection
from app.services.audit import record_audit

router = APIRouter()

@router.get("/", response_model=list[DeviceOut])
def list_devices(
    limit: int | None = Query(default=None, ge=1, le=1000,
                              description="Maximum devices to return. Unset returns all."),
    offset: int = Query(default=0, ge=0, description="Devices to skip, for paging."),
    site: str | None = Query(default=None, description="Exact site match."),
    vendor: str | None = Query(default=None, description="Exact vendor match, case-insensitive."),
    db: Session = Depends(get_db),
    user=Depends(require_permission("devices.view")),
):
    """List devices, optionally filtered and paged.

    Every parameter is optional and the default is the previous behaviour --
    every device, ordered by hostname. That is deliberate: this endpoint has
    existing callers, including a UI that renders whatever it is handed, and a
    default page size would silently truncate them.
    """
    query = db.query(Device)
    if site:
        query = query.filter(Device.site == site)
    if vendor:
        # Case-insensitive on both sides. The API lowercases on write, but this
        # column is read defensively as `device.vendor.lower()` everywhere in
        # services/ -- so the codebase already assumes mixed case can be in
        # there, and a filter that did not would silently miss those rows.
        query = query.filter(func.lower(Device.vendor) == vendor.lower())
    query = query.order_by(Device.hostname).offset(offset)
    if limit is not None:
        query = query.limit(limit)
    return query.all()


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(device_id: int, db: Session = Depends(get_db),
               user=Depends(require_permission("devices.view"))):
    """One device by id.

    Without this, reading one device costs the whole list -- which is what any
    API client integrating against this has to do today.
    """
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Device not found")
    return device

@router.post("/", response_model=DeviceOut)
def create_device(data: DeviceCreate, db: Session = Depends(get_db),
                  user=Depends(require_permission("devices.create"))):
    if db.query(Device).filter(Device.hostname == data.hostname).first():
        raise HTTPException(409, "Hostname already exists")
    device = Device(hostname=data.hostname, management_ip=data.management_ip, vendor=data.vendor.lower(),
        model=data.model, username=data.username, password_encrypted=encrypt_secret(data.password),
        ssh_port=data.ssh_port, site=data.site)
    db.add(device); db.commit(); db.refresh(device)
    record_audit(db, user, "DEVICE_CREATE", "device", device.id, details=f"hostname={device.hostname}")
    return device

@router.patch("/{device_id}", response_model=DeviceOut)
def update_device(device_id: int, data: DeviceUpdate, db: Session = Depends(get_db),
                  user=Depends(require_permission("devices.edit"))):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device: raise HTTPException(404, "Device not found")
    if data.hostname is not None and data.hostname != device.hostname:
        if db.query(Device).filter(Device.hostname == data.hostname, Device.id != device_id).first():
            raise HTTPException(409, "Hostname already exists")
        device.hostname = data.hostname
    if data.management_ip is not None: device.management_ip = data.management_ip
    if data.vendor is not None: device.vendor = data.vendor.lower()
    if data.model is not None: device.model = data.model
    if data.username is not None: device.username = data.username
    if data.password: device.password_encrypted = encrypt_secret(data.password)
    if data.ssh_port is not None: device.ssh_port = data.ssh_port
    if data.site is not None: device.site = data.site
    if data.enabled is not None: device.enabled = data.enabled
    db.commit(); db.refresh(device)
    record_audit(db, user, "DEVICE_UPDATE", "device", device.id, details=f"hostname={device.hostname}")
    return device

@router.delete("/{device_id}")
def delete_device(device_id: int, db: Session = Depends(get_db),
                  user=Depends(require_permission("devices.delete"))):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device: raise HTTPException(404, "Device not found")
    name = device.hostname
    remove_device_schedule(device_id)
    db.query(BackupSchedule).filter(BackupSchedule.device_id == device_id).delete(synchronize_session=False)
    db.query(Backup).filter(Backup.device_id == device_id).delete(synchronize_session=False)
    db.delete(device); db.commit()
    record_audit(db, user, "DEVICE_DELETE", "device", device_id, details=f"hostname={name};backup_files=retained")
    return {"success": True, "message": "Device deleted; backup files were retained"}

@router.post("/{device_id}/test")
def connection_test(device_id: int, db: Session = Depends(get_db),
                    user=Depends(require_permission("devices.test"))):
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device: raise HTTPException(404, "Device not found")
    result = test_connection(device)
    record_audit(db, user, "DEVICE_TEST", "device", device_id,
                 status="SUCCESS" if result.get("success") else "FAILED",
                 details=result.get("message"))
    return result
