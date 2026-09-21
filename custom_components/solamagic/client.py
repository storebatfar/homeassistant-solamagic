from __future__ import annotations
import logging
import asyncio
import binascii

from homeassistant.core import HomeAssistant

from .bluetooth import SolamagicBleClient, is_valid_init_token
from .const import (
    CCCD_CMD,
    CCCD_ENABLE_DELAY_MS,
    CCCD_NTF1,
    CCCD_NTF2,
    CHAR_ALT_F002,
    CHAR_CMD_F001,
    CMD_OFF,
    CMD_OFF_DELAY_MS,
    CMD_OFF_REPEAT_COUNT,
    CMD_ON_100,
    CMD_ON_33,
    CMD_ON_66,
    CONF_DISCONNECT_TIMEOUT,
    CONF_INIT_TOKEN,
    CONF_WRITE_MODE,
    DEFAULT_DISCONNECT_TIMEOUT,
    INIT_DELAY_MS,
)

_LOGGER = logging.getLogger(__name__)

class SolamagicClient:
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry,
                 write_mode: str = "handle",
                 command_char: str | None = None) -> None:
        self._hass = hass
        self._entry = entry
        address: str = entry.data["address"]
        disconnect_timeout = entry.options.get(
            CONF_DISCONNECT_TIMEOUT,
            entry.data.get(CONF_DISCONNECT_TIMEOUT, DEFAULT_DISCONNECT_TIMEOUT)
        )
        self._ble = SolamagicBleClient(hass, address, disconnect_timeout)
        self._cmd_char = command_char or CHAR_CMD_F001
        self._alt_char = CHAR_ALT_F002
        self._write_mode = write_mode
        self._initialized = False

        # Possibly stored init value from previous connection
        self._stored_init: bytes | None = None
        init_hex = entry.data.get(CONF_INIT_TOKEN)
        if init_hex:
            try:
                self._stored_init = binascii.unhexlify(init_hex)
            except Exception:
                self._stored_init = None

    async def _ensure_initialized(self) -> None:
        """
        CRITICAL INITIALIZATION SEQUENCE - based on sniffer analysis!

        This sequence must be run ONCE per connection in exactly this order:

        1. Write initialization payload to handle 0x001F
        2. Enable CCCD on 0x0030 (notifications for 0x002F)
        3. Enable CCCD on 0x0033 (notifications for 0x0032)
        4. Enable CCCD on 0x0029 (notifications for 0x0028) - LAST!

        This order is CRITICAL! Heatlink uses exactly this sequence.
        """
        if self._initialized:
            return

        _LOGGER.info("[%s] Running initialization sequence...", self._entry.data.get("address"))

        # Step 1: Write initialization payload to 0x001F
        # This "unlocks" the device for commands
        _LOGGER.debug("[%s] Step 1: Writing initialization payload to 0x001F", self._entry.data.get("address"))
        used_init = await self._ble.write_init_sequence(self._stored_init)
        # If we got a new (non-zero) init value → save it
        await self._save_init_token(used_init)
        await asyncio.sleep(INIT_DELAY_MS / 1000)

        # Apply handle offset (detected at connection time for Model A/B support)
        offset = self._ble.handle_offset
        cccd_ntf1 = CCCD_NTF1 + offset
        cccd_ntf2 = CCCD_NTF2 + offset
        cccd_cmd  = CCCD_CMD  + offset

        # Step 2: Enable notifications on NTF1 channel (CCCD offset-adjusted)
        _LOGGER.debug("[%s] Step 2: Enabling CCCD 0x%04X (NTF1, offset=%d)", self._entry.data.get("address"), cccd_ntf1, offset)
        try:
            await self._ble.write_cccd(cccd_ntf1, bytes([0x01, 0x00]))
            _LOGGER.debug("[%s] CCCD 0x%04X enabled (notifications)", self._entry.data.get("address"), cccd_ntf1)
        except Exception as e:  # Broad catch OK: CCCD optional, log and continue init
            _LOGGER.warning("[%s] Could not enable CCCD 0x%04X: %s", self._entry.data.get("address"), cccd_ntf1, e)

        await asyncio.sleep(CCCD_ENABLE_DELAY_MS / 1000)

        # Step 3: Enable notifications on NTF2 channel (CCCD offset-adjusted)
        _LOGGER.debug("[%s] Step 3: Enabling CCCD 0x%04X (NTF2, offset=%d)", self._entry.data.get("address"), cccd_ntf2, offset)
        try:
            await self._ble.write_cccd(cccd_ntf2, bytes([0x01, 0x00]))
            _LOGGER.debug("[%s] CCCD 0x%04X enabled (notifications)", self._entry.data.get("address"), cccd_ntf2)
        except Exception as e:  # Broad catch OK: CCCD optional, log and continue init
            _LOGGER.warning("[%s] Could not enable CCCD 0x%04X: %s", self._entry.data.get("address"), cccd_ntf2, e)

        await asyncio.sleep(CCCD_ENABLE_DELAY_MS / 1000)

        # Step 4: Enable CMD notifications (CCCD offset-adjusted) - LAST!
        # This is the command channel - must be enabled last!
        _LOGGER.debug("[%s] Step 4: Enabling CCCD 0x%04X (CMD, offset=%d) - LAST!", self._entry.data.get("address"), cccd_cmd, offset)
        try:
            await self._ble.write_cccd(cccd_cmd, bytes([0x01, 0x00]))
            _LOGGER.debug("[%s] CCCD 0x%04X enabled (notifications)", self._entry.data.get("address"), cccd_cmd)
        except Exception as e:  # Broad catch OK: CCCD optional, log and continue init
            _LOGGER.warning("[%s] Could not enable CCCD 0x%04X: %s", self._entry.data.get("address"), cccd_cmd, e)

        await asyncio.sleep(CCCD_ENABLE_DELAY_MS * 2 / 1000)
        self._initialized = True
        _LOGGER.info("[%s] Initialization sequence complete!", self._entry.data.get("address"))

    async def set_level(self, pct: int) -> None:
        """
        Set heater level to 0/33/66/100%.

        Based on Bluetooth sniffer analysis from the xHeatlink app:

        Initialization (runs automatically on first command):
        1. Write 0x001F: FF FF FF FD 94 34 00 00 00
        2. Enable CCCD 0x0030: 01 00 (notifications)
        3. Enable CCCD 0x0033: 01 00 (notifications)
        4. Enable CCCD 0x0029: 01 00 (notifications) - LAST!

        Command sequence:
        - 33%:  Send 01 21 (1 command in sniffer log)
        - 66%:  Send 01 42 (1 command)
        - 100%: Send 01 64 (1 command)
        - OFF:  Send 00 21 (~21 commands with ~16ms delay)

        All commands use Write Command (response=False) for speed.

        IMPORTANT: The heater does NOT send a separate status notification after the command!
        It only confirms with the same bytes (2 bytes) back on handle 0x0028.
        We must therefore assume the command succeeded and update status manually.

        Args:
            pct: Power level percentage (0, 33, 66, or 100)

        Raises:
            ValueError: If pct is not one of the valid values (0, 33, 66, 100)
        """
        if pct not in (0, 33, 66, 100):
            raise ValueError("pct must be one of 0, 33, 66, 100")

        # CRITICAL: Run initialization sequence on first command
        await self._ensure_initialized()

        _LOGGER.info("[%s] Setting heater to %d%%", self._entry.data.get("address"), pct)

        cmd, repeat = {
            0:   (CMD_OFF,     CMD_OFF_REPEAT_COUNT),  # OFF needs ~21 repeats per the sniffer
            33:  (CMD_ON_33,   1),
            66:  (CMD_ON_66,   1),
            100: (CMD_ON_100,  1),
        }[pct]

        _LOGGER.debug(
            "[%s] Sending %d%% command (%s)%s",
            self._entry.data.get("address"), pct, bytes(cmd).hex(),
            f" x {repeat}" if repeat > 1 else "",
        )

        # Arm the stale-notification filter before writing, so the confirmation
        # that comes back is recognised as the value we asked for.
        self._ble.set_expected_level(pct)

        confirmed = await self._send_command_confirmed(cmd, repeat=repeat)

        if confirmed:
            # No need to update status here: the 2-byte confirmation we just waited
            # for is itself a [power, level] frame, and _notification_handler has
            # already pushed it to the status callback.
            _LOGGER.info("[%s] Heater acknowledged %d%%", self._entry.data.get("address"), pct)
        else:
            # Leave the state alone — reporting success here is what makes a heater
            # that silently ignores commands look like it is working.
            _LOGGER.warning(
                "[%s] Heater did not acknowledge %d%% command (%s) — state left unchanged",
                self._entry.data.get("address"), pct, bytes(cmd).hex(),
            )

    async def _send_command_confirmed(
        self, cmd: bytes, *, repeat: int = 1, timeout: float = 1.0
    ) -> bool:
        """
        Write a command to 0x0028 and wait for the heater to echo it back.

        The echo is the only acknowledgement available: commands are sent as Write
        Command (response=False), so there is no transport-level ACK. The callback
        is installed before the write because the echo can arrive within a few ms.

        Returns True if the heater echoed the command within `timeout`.
        """
        expected = bytes(cmd)
        confirmed = asyncio.Event()

        def confirmation_checker(data: bytes) -> None:
            if data == expected:
                confirmed.set()

        old_callback = self._ble._confirmation_callback
        self._ble._confirmation_callback = confirmation_checker

        try:
            for _ in range(repeat):
                await self._ble.write_handle_raw(cmd, response=False, repeat=1, delay_ms=0)
                if repeat > 1:
                    await asyncio.sleep(CMD_OFF_DELAY_MS / 1000)  # ~16ms between repeats

            try:
                await asyncio.wait_for(confirmed.wait(), timeout)
                return True
            except asyncio.TimeoutError:
                return False
        finally:
            self._ble._confirmation_callback = old_callback

    async def off(self) -> None:
        """
        Turn off the heater.

        This is a convenience method that calls set_level(0).
        """
        await self.set_level(0)

    # Service API (used by __init__.py services)
    async def write_handle_raw(self, data: bytes, response: bool=False,
                              repeat: int=1, delay_ms: int=100) -> None:
        """
        Direct handle writing for services.

        Used by solamagic.write_handle service.

        Args:
            data: Raw bytes to write to handle
            response: Whether to wait for response (default: False)
            repeat: Number of times to repeat command (default: 1)
            delay_ms: Delay between repeats in milliseconds (default: 100)
        """
        await self._ensure_initialized()
        await self._ble.write_handle_raw(data, response=response,
                                         repeat=repeat, delay_ms=delay_ms)

    async def write_handle_any(self, handle: int, data: bytes, response: bool=False,
                              repeat: int=1, delay_ms: int=100) -> None:
        """
        Write to arbitrary handle.

        Used by solamagic.write_handle_any service.

        Args:
            handle: GATT handle number (decimal)
            data: Raw bytes to write
            response: Whether to wait for response (default: False)
            repeat: Number of times to repeat command (default: 1)
            delay_ms: Delay between repeats in milliseconds (default: 100)
        """
        await self._ensure_initialized()
        await self._ble.write_handle_any(handle, data, response=response,
                                         repeat=repeat, delay_ms=delay_ms)

    async def write_uuid_raw(self, char_uuid: str, data: bytes,
                            response: bool=False) -> None:
        """
        Write via UUID.

        Used by solamagic.write_uuid service.

        Args:
            char_uuid: Characteristic UUID string
            data: Raw bytes to write
            response: Whether to wait for response (default: False)
        """
        await self._ensure_initialized()
        await self._ble.write_uuid_simple(char_uuid, data, response=response)

    async def disconnect(self) -> None:
        """
        Disconnect from device.
        Resets initialization status so it runs again on next connection.
        """
        self._initialized = False
        await self._ble.disconnect()

    async def _save_init_token(self, value: bytes) -> None:
        """Save init value in config entry (survives restart)."""
        if not is_valid_init_token(value):
            # Never let a placeholder overwrite a token we already have — that
            # loss is permanent, the real token can only come back from the device.
            return

        hex_value = binascii.hexlify(value).decode("ascii")

        # Avoid unnecessary writes
        data = dict(self._entry.data)
        if data.get(CONF_INIT_TOKEN) == hex_value:
            self._stored_init = value
            return

        data[CONF_INIT_TOKEN] = hex_value
        self._hass.config_entries.async_update_entry(
            self._entry,
            data=data,
        )
        self._stored_init = value
        _LOGGER.info(
            "[%s] Saving new init token: %s",
            self._entry.data.get("address"),
            hex_value,
        )