# -*- coding: utf-8 -*-
from datetime import datetime
from socket import AF_INET, SOCK_DGRAM, socket
from struct import pack, unpack

from zk import const
from zk.attendance import Attendance
from zk.exception import ZKErrorResponse, ZKNetworkError
from zk.user import User


class ZK(object):

    is_connected = False

    __data_recv = None
    __session_id = 0
    __reply_id = 0

    def __init__(self, ip, port=4370, timeout=60):
        self.__address = (ip, port)
        self.__sock = socket(AF_INET, SOCK_DGRAM)
        self.__sock.settimeout(timeout)

    def __create_header(self, command, command_string, checksum, session_id, reply_id):
        """
        Puts a the parts that make up a packet together and packs them into a byte string
        """
        buf = pack('HHHH', command, checksum, session_id, reply_id) + command_string
        buf = unpack('8B' + '%sB' % len(command_string), buf)
        checksum = unpack('H', self.__create_checksum(buf))[0]
        reply_id += 1
        if reply_id >= const.USHRT_MAX:
            reply_id -= const.USHRT_MAX

        buf = pack('HHHH', command, checksum, session_id, reply_id)
        return buf + command_string

    @staticmethod
    def __create_checksum(p):
        """
        Calculates the checksum of the packet to be sent to the time clock
        Copied from zkemsdk.c
        """
        l = len(p)
        checksum = 0
        while l > 1:
            checksum += unpack('H', pack('BB', p[0], p[1]))[0]
            p = p[2:]
            if checksum > const.USHRT_MAX:
                checksum -= const.USHRT_MAX
            l -= 2
        if l:
            checksum = checksum + p[-1]

        while checksum > const.USHRT_MAX:
            checksum -= const.USHRT_MAX

        checksum = ~checksum

        while checksum < 0:
            checksum += const.USHRT_MAX

        return pack('H', checksum)

    @staticmethod
    def __clean_bytes(s):
        return s.decode('windows-1252').strip('\x00')

    def __send_command(self, command=const.CMD_CONNECT, command_string=b'', checksum=0, session_id=0, reply_id=const.USHRT_MAX - 1, response_size=8):
        """
        send command to the terminal
        """
        buf = self.__create_header(command, command_string, checksum, session_id, reply_id)
        try:
            self.__sock.sendto(buf, self.__address)
            self.__data_recv = self.__sock.recv(response_size)
        except Exception as e:
            raise ZKNetworkError(str(e))

        self.__response = unpack('HHHH', self.__data_recv[:8])[0]
        self.__reply_id = unpack('HHHH', self.__data_recv[:8])[3]

        if self.__response in [const.CMD_ACK_OK, const.CMD_PREPARE_DATA]:
            return {
                'status': True,
                'code': self.__response
            }
        else:
            return {
                'status': False,
                'code': self.__response
            }

    def __get_data_size(self):
        """Checks a returned packet to see if it returned CMD_PREPARE_DATA,
        indicating that data packets are to be sent

        Returns the amount of bytes that are going to be sent"""
        response = self.__response
        if response == const.CMD_PREPARE_DATA:
            size = unpack('I', self.__data_recv[8:12])[0]
            return size
        else:
            return 0

    def __decode_time(self, t):
        """
        Decode a timestamp retrieved from the timeclock
        """

        t = int.from_bytes(t, byteorder="little")
        return datetime.fromtimestamp(t+936414000) # 60*60*24*31*12*29


    def connect(self):
        """
        Connect to the device
        """

        cmd_response = self.__send_command(
            command=const.CMD_CONNECT,
            session_id=0,
            reply_id=const.USHRT_MAX - 1,
            response_size=8)
        if cmd_response.get('status'):
            self.is_connected = True
            # set the session id
            self.__session_id = unpack('HHHH', self.__data_recv[:8])[2]
            return self
        else:
            raise ZKErrorResponse("Invalid response")

    def disconnect(self):
        """
        Disconnect from the connected device
        """

        cmd_response = self.__send_command(
            command=const.CMD_EXIT,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            self.is_connected = False
            self.__session_id = 0
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def disable_device(self):
        """
        Disable (lock) device, ensure no activity when process run
        """

        cmd_response = self.__send_command(
            command=const.CMD_DISABLEDEVICE,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def enable_device(self):
        """
        Enable the connected device
        """

        cmd_response = self.__send_command(
            command=const.CMD_ENABLEDEVICE,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def get_firmware_version(self):
        """
        Return the firmware version
        """

        cmd_response = self.__send_command(
            command=const.CMD_GET_VERSION,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            firmware_version = self.__clean_bytes(self.__data_recv[8:])
            return firmware_version
        else:
            raise ZKErrorResponse("Invalid response")

    def get_serial_number(self):
        """
        Return the serial number
        """

        cmd_response = self.__send_command(
            command=const.CMD_OPTIONS_RRQ,
            command_string=b'~SerialNumber',
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            serial_number = self.__clean_bytes(self.__data_recv[8:]).split('=')[-1]
            return serial_number
        else:
            raise ZKErrorResponse("Invalid response")

    def get_time(self):
        """
        return the time
        """

        cmd_response = self.__send_command(
            command=const.CMD_GET_TIME,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)

        if cmd_response.get("status"):
            return self.__decode_time(self.__data_recv[8:])
        else:
            raise ZKErrorResponse("Invalid response")

    def restart(self):
        """
        restart the device
        """

        cmd_response = self.__send_command(
            command=const.CMD_RESTART,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def poweroff(self):
        """
        shutdown the device
        """

        cmd_response = self.__send_command(
            command=const.CMD_POWEROFF,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def test_voice(self):
        """
        play test voice
        """

        cmd_response = self.__send_command(
            command=const.CMD_TESTVOICE,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=8)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def set_user(self, uid, name, privilege, password='', group_id='', user_id=''):
        """
        Create or update user by uid
        """

        uid = chr(uid % 256) + chr(uid >> 8)
        if privilege not in [const.USER_DEFAULT, const.USER_ADMIN]:
            privilege = const.USER_DEFAULT
        privilege = chr(privilege)
        cmd_response = self.__send_command(
            command=const.CMD_USER_WRQ,
            command_string=pack('2sc8s28sc7sx24s', uid, privilege, password, name, chr(0), group_id, user_id),
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def delete_user(self, uid):
        """
        Delete specific user by uid
        """

        uid = chr(uid % 256) + chr(uid >> 8)
        cmd_response = self.__send_command(
            command=const.CMD_DELETE_USER,
            command_string=pack('2s', uid),
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def get_users(self):
        """
        Return all users
        """

        cmd_response = self.__send_command(
            command=const.CMD_USERTEMP_RRQ,
            command_string=chr(const.FCT_USER).encode('ascii'),
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        users = []
        if cmd_response.get('status'):
            if cmd_response.get('code') == const.CMD_PREPARE_DATA:
                data_size = self.__get_data_size()
                user_data = []
                while data_size > 0:
                    data_recv = self.__sock.recv(1032)
                    user_data.append(data_recv)
                    data_size -= 1024

                data_recv = self.__sock.recv(8)
                response = unpack('HHHH', data_recv[:8])[0]
                if response == const.CMD_ACK_OK:
                    if user_data:
                        # The first 4 bytes don't seem to be related to the user
                        for x in range(len(user_data)):
                            if x > 0:
                                user_data[x] = user_data[x][8:]

                        user_data = b''.join(user_data)
                        user_data = user_data[12:]
                        while len(user_data) >= 72:
                            uid, privilege, password, name, _, group_id, user_id = unpack('2sc8s28sc7sx24s', user_data.ljust(72)[:72])
                            uid = int.from_bytes(uid, byteorder='little')
                            privilege = int.from_bytes(privilege, byteorder='little')
                            password = self.__clean_bytes(password)
                            name = self.__clean_bytes(name)
                            group_id = int.from_bytes(group_id, byteorder='little')
                            user_id = self.__clean_bytes(user_id)
                            user = User(uid, name, privilege, password, group_id, user_id)
                            users.append(user)

                            user_data = user_data[72:]
                else:
                    raise ZKErrorResponse("Invalid response")

        return users

    def cancel_capture(self):
        """
        Cancel capturing finger
        """

        command = const.CMD_CANCELCAPTURE
        cmd_response = self.__send_command(command=command)
        print(cmd_response)

    def verify_user(self):
        """
        verify finger
        """

        command = const.CMD_STARTVERIFY
        # uid = chr(uid % 256) + chr(uid >> 8)
        cmd_response = self.__send_command(command=command)
        print(cmd_response)

    def enroll_user(self, uid):
        """
        start enroll user
        """

        command = const.CMD_STARTENROLL
        uid = chr(uid % 256) + chr(uid >> 8)
        command_string = pack('2s', uid)
        cmd_response = self.__send_command(command=command, command_string=command_string)
        print(cmd_response)

    def clear_data(self):
        """
        Clear all data (include: user, attendance report, finger database )
        """

        cmd_response = self.__send_command(
            command=const.CMD_CLEAR_DATA,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")

    def get_attendance(self):
        """
        Return all attendance record
        """

        cmd_response = self.__send_command(
            command=const.CMD_ATTLOG_RRQ,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        attendances = []
        if cmd_response.get('status'):
            if cmd_response.get('code') == const.CMD_PREPARE_DATA:
                data_size = self.__get_data_size()
                attendance_data = []
                while data_size > 0:
                    data_recv = self.__sock.recv(1032)
                    attendance_data.append(data_recv)
                    data_size -= 1024

                data_recv = self.__sock.recv(8)
                response = unpack('HHHH', data_recv[:8])[0]
                if response == const.CMD_ACK_OK:
                    if attendance_data:
                        # The first 4 bytes don't seem to be related to the user
                        for x in range(len(attendance_data)):
                            if x > 0:
                                attendance_data[x] = attendance_data[x][8:]

                        attendance_data = ''.join(attendance_data)
                        attendance_data = attendance_data[14:]
                        while len(attendance_data) >= 38:
                            user_id, _, timestamp, status, _ = unpack('24sc4sc10s', attendance_data.encode('ascii').ljust(40)[:40])

                            user_id = user_id.strip('\x00|\x01\x10x')
                            timestamp = self.__decode_time(timestamp)
                            status = int(status.encode("hex"), 16)

                            attendance = Attendance(user_id, timestamp, status)
                            attendances.append(attendance)

                            attendance_data = attendance_data[40:]
                else:
                    raise ZKErrorResponse("Invalid response")

        return attendances

    def clear_attendance(self):
        """
        Clear all attendance record
        """

        cmd_response = self.__send_command(
            command=const.CMD_CLEAR_ATTLOG,
            session_id=self.__session_id,
            reply_id=self.__reply_id,
            response_size=1024)
        if cmd_response.get('status'):
            return True
        else:
            raise ZKErrorResponse("Invalid response")
