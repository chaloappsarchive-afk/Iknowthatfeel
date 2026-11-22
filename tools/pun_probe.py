#!/usr/bin/env python3
"""pun_probe.py — пассивный наблюдатель PUN2-трафика.

Зачем
-----
`analysis/bot-destroy-pun.md` объясняет, ПОЧЕМУ бот в Chicken Gun удаляется
локально (`BotController.DestroySelf`), а не сетевым событием. Этот скрипт
проверяет вывод экспериментально: подключается к Photon как обычный PUN2-клиент
и логирует все входящие события, разбирая их по кодам PUN.

Ключевой вопрос, на который отвечает прогон:
  * приходит ли на ботов событие **202 INSTANTIATION** (сетевой спавн) —
    если нет, значит каждый клиент спавнит мобов сам;
  * приходит ли на ботов событие **204 DESTROY** (сетевое удаление) —
    если нет, значит удаление локальное;
  * какие **200 RPC** с именами из `BotController` летают (`DieR`, `DamageRPC`,
    `StartAttackR`, `StopAttackR`).

Скрипт НИЧЕГО не отправляет в игровом трафике: не вызывает RPC, не создаёт и не
уничтожает объекты, не сериализует состояние. Только handshake + вход в комнату
+ чтение событий.

Библиотека
----------
PUN2-клиент завендорен в `third_party/Photon-PUN2-Python` (чистый stdlib, Python 3.10+,
MIT; происхождение и SHA апстрима — в `third_party/Photon-PUN2-Python/VENDORED.txt`).
`--lib` по умолчанию указывает именно туда, так что клонировать ничего не нужно:

    python3 tools/pun_probe.py check
    python3 tools/pun_probe.py create --room MyProbeRoom --app-version 116

AppId
-----
В git AppId не лежит. Скрипт берёт его из (по порядку):
  1. `--app-id`,
  2. переменной окружения `PHOTON_APP_ID`,
  3. файла `work/photon_appid.txt` (каталог `work/` в `.gitignore`).

Режимы
------
  check   — офлайн: печатает таблицу кодов событий и что искать. Сеть не нужна.
  create  — создать СВОЮ пустую комнату и послушать её (безопасно, никто не мешает).
            Годится, чтобы проверить AppId / appversion / регион.
  join    — войти в существующую комнату и только слушать.
            ВНИМАНИЕ: в живом матче это добавляет фантомного игрока и может
            помешать остальным. Используй только для своей собственной комнаты.

Примеры
-------
    python3 tools/pun_probe.py check
    python3 tools/pun_probe.py create --room MyTestRoom --app-version 116
    python3 tools/pun_probe.py join   --room ROOM_NAME --app-version 116 --seconds 120 --out work/events.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------- офлайн-часть

PUN_EVENTS = {
    200: ("RPC", "вызов метода на объекте по viewId; САМ ПО СЕБЕ ничего не удаляет"),
    201: ("SEND_SERIALIZE", "пакет синхронизации PhotonView (ненадёжный)"),
    202: ("INSTANTIATION", "сетевой спавн объекта: имя префаба + viewId'ы"),
    203: ("CLOSE_CONNECTION", "сервер просит закрыть соединение"),
    204: ("DESTROY", "сетевое удаление объекта: {0: viewId}"),
    205: ("REMOVE_CACHED_RPCS", "чистка кэша RPC"),
    206: ("SEND_SERIALIZE_RELIABLE", "пакет синхронизации PhotonView (надёжный)"),
    207: ("DESTROY_PLAYER", "удалить все объекты игрока: {0: actorNr}"),
    209: ("OWNERSHIP_REQUEST", "запрос владения"),
    210: ("OWNERSHIP_TRANSFER", "передача владения"),
    211: ("VACANT_VIEW_IDS", "освободившиеся viewId"),
    212: ("OWNERSHIP_UPDATE", "обновление владения (PUN 2.55)"),
}

REALTIME_EVENTS = {
    255: "JOIN (игрок вошёл)",
    254: "LEAVE (игрок вышел) -> клиент сам удаляет все его объекты",
    253: "PROPERTIES_CHANGED",
    251: "ERROR_INFO",
    250: "CACHE_SLICE_CHANGED",
}

# Методы из global-metadata.dat, которые нас интересуют в RPC (событие 200).
WATCH_RPCS = {
    # BotController (тип rid 933, dt 4333)
    "DieR": "BotController.DieR (rid 5699, 1 пар.) — смерть бота по сети",
    "DamageRPC": "BotController.DamageRPC (rid 5697, 0 пар.)",
    "StartAttackR": "BotController.StartAttackR (rid 5704)",
    "StopAttackR": "BotController.StopAttackR (rid 5706)",
    "UpdateHP": "BotController.UpdateHP (rid 5698, 1 пар.)",
    # другие боты
    "AttackPlayer": "OtchimBot/HuggyWuggyBot.AttackPlayer (2 пар.)",
    "Explode": "BotAnimEvents.Explode (rid 5675) / RaceCarController.Explode",
    "DestroySelf": "если вдруг придёт по сети — вывод документа неверен",
    # игроки
    "RespawnRPC": "CharacterMotor.RespawnRPC",
    "OnDie": "CharacterMotor.OnDie",
    "RPC_SecureDestroyPlayer": "TauntAnimationsEventsHandler (rid 6291)",
}


def cmd_check(_: argparse.Namespace) -> int:
    print("=== коды событий PUN2 (PunEvent) ===")
    for code, (name, note) in sorted(PUN_EVENTS.items()):
        print("  %3d  %-26s %s" % (code, name, note))
    print("\n=== коды событий Realtime (EventCode) ===")
    for code, note in sorted(REALTIME_EVENTS.items()):
        print("  %3d  %s" % (code, note))
    print("\n=== структура RPC (событие 200), байтовые ключи Hashtable ===")
    print("  0 viewId | 1 levelPrefix | 2 timestamp | 3 methodName(строка) | 4 параметры | 5 shortcut(индекс вместо имени)")
    print("\n=== структура INSTANTIATION (202) ===")
    print("  0 prefabName | 1 position | 2 rotation | 3 group | 4 viewIds | 5 data | 6 timestamp | 7 instantiationId | 8 levelPrefix")
    print("\n=== viewId ===")
    print("  viewId = actorNumber * 1000 + subId;  owner = viewId // 1000")
    print("  owner == 0  -> scene object (создан в сцене, не по сети)")
    print("\n=== какие RPC-имена искать (из global-metadata.dat) ===")
    for name, note in WATCH_RPCS.items():
        print("  %-26s %s" % (name, note))
    print("\n=== что должно получиться, если разбор верен ===")
    print("  * на мобов НЕ приходит 202 INSTANTIATION  -> спавн локальный на каждом клиенте")
    print("  * на мобов НЕ приходит 204 DESTROY        -> удаление локальное (Object.Destroy)")
    print("  * на мобов ПРИХОДИТ 200 RPC 'DieR'        -> смерть рассылается как RPC")
    print("  * 204/207 приходят только на объекты ИГРОКОВ (owner = actorNr != 0)")
    return 0


# ---------------------------------------------------------------- сеть

MAX_VIEW_IDS = 1000


class Probe:
    """Read-only логгер событий."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.events: list[dict] = []
        self.rpc_names: dict[str, int] = {}
        self.destroyed_views: list[int] = []
        self.instantiated: list[dict] = []
        self.left_actors: list[int] = []
        self.connected = False   # подключились ли к мастер-серверу
        self.in_room = False     # вошли ли в комнату
        self.error: str | None = None
        self.t0 = time.time()
        self._out = open(args.out, "w", encoding="utf-8") if args.out else None

    # -- helpers -----------------------------------------------------------

    def log(self, kind: str, **fields) -> None:
        rec = {"t": round(time.time() - self.t0, 3), "kind": kind, **fields}
        self.events.append(rec)
        line = json.dumps(rec, ensure_ascii=False, default=str)
        if self._out:
            self._out.write(line + "\n")
            self._out.flush()
        if not self.args.quiet:
            print(line)

    @staticmethod
    def owner_of(view_id: int) -> int:
        return int(view_id) // MAX_VIEW_IDS

    # -- handler -----------------------------------------------------------

    def on_event(self, event) -> None:
        from photon.protocol.constants import ParameterCode, PunEvent

        code = int(event.code)
        p = event.parameters
        sender = p.get(ParameterCode.ACTOR_NR, 0)
        data = p.get(ParameterCode.DATA)

        if code == PunEvent.RPC:
            self._on_rpc(data, sender)
        elif code == PunEvent.INSTANTIATION:
            self._on_instantiate(data, sender)
        elif code == PunEvent.DESTROY:
            vid = self._key0(data)
            if vid is not None:
                self.destroyed_views.append(int(vid))
                self.log("DESTROY(204)", viewId=int(vid), owner=self.owner_of(vid),
                         scene_object=self.owner_of(vid) == 0, sender=sender)
        elif code == PunEvent.DESTROY_PLAYER:
            act = self._key0(data)
            self.log("DESTROY_PLAYER(207)", actorNr=act, sender=sender)
        elif code in (PunEvent.SEND_SERIALIZE, PunEvent.SEND_SERIALIZE_RELIABLE):
            self.log("SERIALIZE(%d)" % code, sender=sender,
                     entries=len(data) - 2 if isinstance(data, (list, tuple)) else None)
        elif code == 254:  # EventCode.LEAVE
            self.left_actors.append(int(sender))
            self.log("LEAVE(254)", actorNr=sender)
        elif code == 255:  # EventCode.JOIN
            self.log("JOIN(255)", actorNr=sender)
        elif code == 253:  # PROPERTIES_CHANGED
            self.log("PROPERTIES_CHANGED(253)", sender=sender)
        else:
            self.log("EVENT(%d)" % code, sender=sender, data=str(data)[:200])

    @staticmethod
    def _key0(data):
        if data is None:
            return None
        if isinstance(data, dict):
            return data.get(0)
        return data

    def _on_rpc(self, data, sender) -> None:
        if not isinstance(data, dict):
            self.log("RPC(200)", raw=str(data)[:200], sender=sender)
            return
        view_id = data.get(0)
        method = data.get(3)
        shortcut = data.get(5)
        args = data.get(4)
        ts = data.get(2)
        name = method if method is not None else ("shortcut#%s" % shortcut)
        self.rpc_names[str(name)] = self.rpc_names.get(str(name), 0) + 1
        watched = WATCH_RPCS.get(str(name))
        self.log("RPC(200)", viewId=view_id,
                 owner=self.owner_of(view_id) if view_id else None,
                 method=name, args=str(args)[:300], timestamp=ts, sender=sender,
                 watched=watched)

    def _on_instantiate(self, data, sender) -> None:
        if not isinstance(data, dict):
            self.log("INSTANTIATION(202)", raw=str(data)[:200], sender=sender)
            return
        prefab = data.get(0)
        view_ids = data.get(4)
        rec = {"prefab": prefab, "viewIds": view_ids, "sender": sender}
        self.instantiated.append(rec)
        self.log("INSTANTIATION(202)", prefab=prefab, viewIds=str(view_ids),
                 owners=[self.owner_of(v) for v in (view_ids or []) if isinstance(v, int)],
                 sender=sender)

    # -- summary -----------------------------------------------------------

    def summary(self) -> None:
        print("\n" + "=" * 72)
        print("ИТОГ за %.1f с" % (time.time() - self.t0))
        print("=" * 72)
        print("всего событий: %d" % len(self.events))
        print("RPC-имена (событие 200):")
        if self.rpc_names:
            for name, n in sorted(self.rpc_names.items(), key=lambda kv: -kv[1]):
                mark = "  <== %s" % WATCH_RPCS[name] if name in WATCH_RPCS else ""
                print("   %5d × %-28s%s" % (n, name, mark))
        else:
            print("   (не видели ни одного RPC)")
        print("INSTANTIATION (202): %d шт." % len(self.instantiated))
        for rec in self.instantiated[:20]:
            print("   prefab=%-28s viewIds=%s" % (rec["prefab"], rec["viewIds"]))
        print("DESTROY (204): %d шт." % len(self.destroyed_views))
        scene = [v for v in self.destroyed_views if self.owner_of(v) == 0]
        owned = [v for v in self.destroyed_views if self.owner_of(v) != 0]
        if self.destroyed_views:
            print("   scene-объекты (owner 0): %d, объекты игроков: %d" % (len(scene), len(owned)))
            print("   viewId: %s" % self.destroyed_views[:30])
        print("LEAVE (254): %s" % (self.left_actors or "—"))
        print("\nВЫВОД:")
        if not self.connected:
            print("   ПОДКЛЮЧЕНИЯ НЕ БЫЛО%s — никаких выводов сделать нельзя." %
                  (" (%s)" % self.error if self.error else ""))
            print("   Проверь: открыт ли UDP-выход на ns.photonengine.io:5058,")
            print("   правильный ли AppId/AppVersion/регион.")
            if self._out:
                self._out.close()
            return
        if not self.in_room:
            print("   подключились к мастеру, но в комнату не вошли%s —" %
                  (" (%s)" % self.error if self.error else ""))
            print("   скорее всего не совпадает AppVersion или комната не найдена.")
            if self._out:
                self._out.close()
            return
        mob_rpc = [n for n in self.rpc_names if n in WATCH_RPCS]
        if not self.instantiated and not self.destroyed_views:
            print("   в комнате не пришли ни 202, ни 204 => спавн и удаление НЕ сетевые,")
            print("   что совпадает с разбором: бот создаётся и удаляется локально,")
            print("   по сети ходят только RPC%s." % (
                " (%s)" % ", ".join(sorted(mob_rpc)) if mob_rpc else ""))
            if not self.events:
                print("   НО: событий вообще не было — возможно, в комнате никто не играл.")
        else:
            print("   пришли 202/204 => часть объектов всё же сетевая;")
            print("   смотри, у каких viewId owner != 0 (это объекты игроков).")
        if self._out:
            self._out.close()
            print("\nлог записан: %s" % self.args.out)


def resolve_app_id(args: argparse.Namespace) -> str | None:
    if args.app_id:
        return args.app_id
    env = os.environ.get("PHOTON_APP_ID")
    if env:
        return env.strip()
    for cand in (Path("work/photon_appid.txt"), Path(__file__).resolve().parent.parent / "work/photon_appid.txt"):
        if cand.exists():
            return cand.read_text(encoding="utf-8").strip()
    return None


async def run_async(args: argparse.Namespace, probe: Probe) -> int:
    from photon.bot import PhotonBot  # noqa: F401  (проверка импорта библиотеки)
    from photon.realtime.client import LoadBalancingClient

    app_id = resolve_app_id(args)
    if not app_id:
        print("Нужен AppId: --app-id, или PHOTON_APP_ID, или work/photon_appid.txt", file=sys.stderr)
        return 2
    app_version = args.app_version + ("_%s" % args.pun_suffix if args.pun_suffix else "")
    print("AppId       : %s…%s (длина %d)" % (app_id[:4], app_id[-4:], len(app_id)))
    print("AppVersion  : %r" % app_version)
    print("Регион      : %s" % args.region)
    print("Ник         : %r" % args.nick)
    print("Комната     : %r (%s)" % (args.room, "создаём свою" if args.mode == "create" else "входим в существующую"))
    if args.mode == "join":
        print("\nВНИМАНИЕ: вход в чужой живой матч добавляет фантомного игрока и может\n"
              "          помешать остальным. Заходи только в свою собственную комнату.\n")

    client = LoadBalancingClient(app_id, app_version, region=args.region,
                                 nick_name=args.nick, user_id=args.user_id)
    client.event_handlers.append(probe.on_event)

    try:
        await client.connect_to_master()
    except Exception as exc:  # noqa: BLE001
        probe.error = "%s: %s" % (type(exc).__name__, exc)
        return 1
    probe.connected = True
    probe.log("STATE", state=str(client.state), master=client.master_address)
    print("подключились к мастеру: %s" % client.master_address)

    from photon.realtime import operations as ops
    try:
        if args.mode == "create":
            room = await client.create_room(args.room, ops.RoomOptions(
                max_players=args.max_players, is_visible=args.visible, is_open=True))
        else:
            room = await client.join_room(args.room)
    except Exception as exc:  # noqa: BLE001
        probe.error = "%s: %s" % (type(exc).__name__, exc)
        return 1
    probe.in_room = True
    probe.log("STATE", state=str(client.state), room=str(room), game=client.game_address,
              actorNr=client.local_player.actor_number)
    print("в комнате %r, мой actorNr=%s" % (room.name, client.local_player.actor_number))
    print("слушаю %d с (Ctrl-C — остановить и получить итог)\n" % args.seconds)

    try:
        await asyncio.sleep(args.seconds)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("check", "create", "join"),
                    help="check — офлайн-справка; create — своя комната; join — чужая (только чтение)")
    ap.add_argument("--lib", default=None,
                    help="путь к Photon-PUN2-Python (по умолчанию — завендоренный "
                         "third_party/Photon-PUN2-Python)")
    ap.add_argument("--room", help="имя комнаты")
    ap.add_argument("--region", default="eu")
    ap.add_argument("--nick", default="pun_probe")
    ap.add_argument("--user-id", default=None)
    ap.add_argument("--app-id", default=None, help="Photon AppId (иначе PHOTON_APP_ID / work/photon_appid.txt)")
    ap.add_argument("--app-version", default="116")
    ap.add_argument("--pun-suffix", default="", help="добавить '_2.55' к appversion, если сервер требует PUN-версию")
    ap.add_argument("--seconds", type=float, default=120.0)
    ap.add_argument("--max-players", type=int, default=8)
    ap.add_argument("--visible", action="store_true", help="создать комнату видимой в лобби")
    ap.add_argument("--out", default=None, help="писать события в JSONL-файл")
    ap.add_argument("--quiet", action="store_true", help="не печатать каждое событие")
    args = ap.parse_args(argv)

    if args.mode == "check":
        return cmd_check(args)

    if not args.room:
        print("Нужен --room NAME", file=sys.stderr)
        return 2
    default_lib = Path(__file__).resolve().parent.parent / "third_party" / "Photon-PUN2-Python"
    lib = Path(args.lib).resolve() if args.lib else default_lib
    if not (lib / "photon" / "bot.py").exists():
        print("В %s нет photon/bot.py — укажи --lib PATH (клон Photon-PUN2-Python)" % lib,
              file=sys.stderr)
        return 2
    sys.path.insert(0, str(lib))
    print("библиотека PUN2: %s" % lib)

    probe = Probe(args)
    try:
        rc = asyncio.run(run_async(args, probe))
    except Exception as exc:  # noqa: BLE001 — нам нужен любой сбой наружу
        sys.stdout.flush()
        probe.error = probe.error or "%s: %s" % (type(exc).__name__, exc)
        print("СБОЙ: %s" % probe.error, file=sys.stderr)
        rc = 1
    probe.summary()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
