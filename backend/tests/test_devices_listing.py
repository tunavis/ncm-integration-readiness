"""Listing, filtering and reading devices.

The endpoints are called directly, so the suite needs no test client and no
running server. What must hold is that the new parameters are additive: an
existing caller passing nothing must get exactly what it got before.
"""

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.devices import get_device, list_devices
from app.core.database import Base
from app.models.device import Device


def device(hostname, vendor="juniper", site="JHB-DC1"):
    return Device(
        hostname=hostname,
        management_ip="10.0.0.1",
        vendor=vendor,
        username="ncm-svc",
        password_encrypted="x",
        ssh_port=22,
        site=site,
        enabled=True,
    )


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine, tables=[Device.__table__])
    session = sessionmaker(bind=engine)()
    session.add_all(
        [
            device("cpt-edge-01", vendor="arista", site="CPT-DC1"),
            device("jhb-core-01", vendor="juniper", site="JHB-DC1"),
            device("jhb-core-02", vendor="Huawei", site="JHB-DC1"),
        ]
    )
    session.commit()
    try:
        yield session
    finally:
        session.close()


def listed(db, **kwargs):
    parameters = {"limit": None, "offset": 0, "site": None, "vendor": None, **kwargs}
    return [d.hostname for d in list_devices(db=db, user=None, **parameters)]


class TestTheDefaultIsUnchanged:
    def test_no_parameters_returns_every_device_by_hostname(self, db):
        """The previous behaviour exactly. A default page size here would
        silently truncate the UI that already calls this."""
        assert listed(db) == ["cpt-edge-01", "jhb-core-01", "jhb-core-02"]


class TestPaging:
    def test_limit_bounds_the_page(self, db):
        assert listed(db, limit=2) == ["cpt-edge-01", "jhb-core-01"]

    def test_offset_skips(self, db):
        assert listed(db, offset=1) == ["jhb-core-01", "jhb-core-02"]

    def test_limit_and_offset_page_through_without_gaps_or_repeats(self, db):
        first = listed(db, limit=2, offset=0)
        second = listed(db, limit=2, offset=2)

        assert first + second == ["cpt-edge-01", "jhb-core-01", "jhb-core-02"]

    def test_an_offset_past_the_end_is_empty_not_an_error(self, db):
        assert listed(db, offset=99) == []


class TestFiltering:
    def test_by_site(self, db):
        assert listed(db, site="CPT-DC1") == ["cpt-edge-01"]

    def test_by_vendor(self, db):
        assert listed(db, vendor="arista") == ["cpt-edge-01"]

    def test_vendor_matching_ignores_case(self, db):
        """Vendors are lowercased on write, so a caller passing 'Huawei' — the
        spelling the vendor itself uses — must still match."""
        assert listed(db, vendor="Huawei") == ["jhb-core-02"]

    def test_filters_combine_with_paging(self, db):
        assert listed(db, site="JHB-DC1", limit=1) == ["jhb-core-01"]

    def test_a_filter_matching_nothing_is_empty(self, db):
        assert listed(db, vendor="cisco") == []


class TestReadingOneDevice:
    def test_a_device_is_returned_by_id(self, db):
        wanted = db.query(Device).filter(Device.hostname == "jhb-core-01").one()

        assert get_device(device_id=wanted.id, db=db, user=None).hostname == "jhb-core-01"

    def test_an_unknown_device_is_404(self, db):
        with pytest.raises(HTTPException) as refusal:
            get_device(device_id=9999, db=db, user=None)

        assert refusal.value.status_code == 404


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
