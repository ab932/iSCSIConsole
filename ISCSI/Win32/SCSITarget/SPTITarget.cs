/* Copyright (C) 2012-2016 Tal Aloni <tal.aloni.il@gmail.com>.
 * Copyright (C) 2017 Alex Bowden <alex.bowden@outlook.com>.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using DiskAccessLibrary;
using Utilities;

namespace SCSI
{
    // An excellent C# example of SPTI can be seen here:
    // https://github.com/brandonlw/Psychson/blob/master/DriveCom/DriveCom/PhisonDevice.cs
    public class SPTITarget : SCSITarget
    {
        public const int IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014;
        public const int SCSI_TIMEOUT = 60;
        public const byte TAPE_DEVICE = 0x01; // Sequential access device
        public const byte DISK_DEVICE = 0x00; // Direct access block device

        public event EventHandler<LogEntry> OnLogEntry;

        private string m_path;
        private SafeHandle m_handle;

        private class LogicalUnit
        {
            public uint DeviceType;
            public bool BlockSizeIsSet; // TODO
            public uint BlockSize;
        }

        private IDictionary<int, LogicalUnit> m_luns = new Dictionary<int, LogicalUnit>();

        public SPTITarget(string path)
        {
            m_path = path;
            m_handle = HandleUtils.GetFileHandle(m_path, FileAccess.ReadWrite, ShareMode.ReadWrite);
        }

        [StructLayout(LayoutKind.Sequential)]
        class SCSI_PASS_THROUGH_DIRECT
        {
            private const int _CDB_LENGTH = 16;

            public short Length;
            public byte ScsiStatus;
            public byte PathId;
            public byte TargetId;
            public byte Lun;
            public byte CdbLength;
            public byte SenseInfoLength;
            public byte DataIn;
            public uint DataTransferLength;
            public uint TimeOutValue;
            public IntPtr DataBuffer;
            public uint SenseInfoOffset;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = _CDB_LENGTH)]
            public byte[] Cdb;

            public SCSI_PASS_THROUGH_DIRECT()
            {
                Cdb = new byte[_CDB_LENGTH];
            }
        };

        [StructLayout(LayoutKind.Sequential)]
        class SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER
        {
            private const int _SENSE_LENGTH = 32;
            internal SCSI_PASS_THROUGH_DIRECT spt = new SCSI_PASS_THROUGH_DIRECT();

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = _SENSE_LENGTH)]
            internal byte[] sense;

            public SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER()
            {
                sense = new byte[_SENSE_LENGTH];
            }
        };

        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DeviceIoControl(SafeHandle hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        /// <summary>
        /// This takes the iSCSI command and forwards it to a SCSI Passthrough device. It then returns the response.
        /// </summary>
        public override SCSIStatusCodeName ExecuteCommand(byte[] commandBytes, LUNStructure lun, byte[] data, out byte[] response)
        {
            SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER scsi = null;
            IntPtr inBuffer = IntPtr.Zero;
            response = new byte[0];

            // SPTI only supports up to 16 byte CDBs
            if (commandBytes.Length > 16)
            {
                response = VirtualSCSITarget.FormatSenseData(SenseDataParameter.GetIllegalRequestUnsupportedCommandCodeSenseData());
                return SCSIStatusCodeName.CheckCondition;
            }

            // Create the Logical Unit dictionary entry
            if (!m_luns.ContainsKey((int)lun))
            {
                LogicalUnit newLun = new LogicalUnit();
                newLun.BlockSizeIsSet = false;
                m_luns.Add((int)lun, newLun);
            }

            // Pad all CDBs to 16 bytes
            Array.Resize(ref commandBytes, 16);

            // Forward SCSI command to target
            try {
                Log(Severity.Verbose, "SCSI Command: (0x{0})", commandBytes[0].ToString("X"));
                Log(Severity.Debug, "Data Length: {0}", data.Length);

                scsi = new SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER();
                scsi.spt.Cdb = commandBytes;
                scsi.spt.Length = (short)Marshal.SizeOf(scsi.spt);
                scsi.spt.Lun = (byte)lun;
                scsi.spt.CdbLength = (byte)commandBytes.Length;

                // DATA OUT (Initiator to target, WRITE)
                if (data != null && data.Length > 0)
                {
                    scsi.spt.DataIn = (byte)SCSIDataDirection.Out;
                    scsi.spt.DataTransferLength = (uint)data.Length;
                }
                else
                {
                    // DATA IN (Initiator from target, READ)
                    scsi.spt.DataIn = (byte)SCSICommandParser.GetDataDirection(commandBytes);
                    if ((SCSIDataDirection)scsi.spt.DataIn == SCSIDataDirection.In)
                    {
                        scsi.spt.DataTransferLength = GetDataInTransferLength(commandBytes, (byte)lun);
                    }
                    else
                    {
                        scsi.spt.DataTransferLength = 0; // No data!
                    }
                    
                }
                Log(Severity.Debug, "Transfer Length: {0}", scsi.spt.DataTransferLength);
                scsi.spt.TimeOutValue = SCSI_TIMEOUT;
                scsi.spt.DataBuffer = Marshal.AllocHGlobal((int)scsi.spt.DataTransferLength);
                scsi.spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER), "sense");
                scsi.spt.SenseInfoLength = (byte)scsi.sense.Length;

                // Copy data from initiator to the SPTI data buffer
                if (data != null && data.Length > 0)
                {
                    Marshal.Copy(data, 0, scsi.spt.DataBuffer, data.Length);
                }

                uint bytesReturned;
                inBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(scsi));
                uint size = (uint)Marshal.SizeOf(scsi);
                Marshal.StructureToPtr(scsi, inBuffer, true);

                if (!DeviceIoControl(m_handle, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                    inBuffer, size, inBuffer, size, out bytesReturned, IntPtr.Zero))
                {
                    int lastError = Marshal.GetLastWin32Error();
                    Log(Severity.Error, "DeviceIoControl Error: {0}", lastError);
                    response = VirtualSCSITarget.FormatSenseData(SenseDataParameter.GetIllegalRequestUnsupportedCommandCodeSenseData());
                    return SCSIStatusCodeName.CheckCondition;
                }
                else
                {
                    Marshal.PtrToStructure(inBuffer, scsi);
                    if (scsi.spt.ScsiStatus != 0)
                    {
                        Log(Severity.Verbose, "SCSI Status: {0}", scsi.spt.ScsiStatus);
                        Log(Severity.Verbose, "SCSI Sense: {0}", BitConverter.ToString(scsi.sense));
                        // SCSI Sense != GOOD
                        response = new byte[scsi.sense.Length + 2];
                        BigEndianWriter.WriteUInt16(response, 0, (ushort)scsi.sense.Length);
                        ByteWriter.WriteBytes(response, 2, scsi.sense);
                        // XXX: Should directly return scsi.spt.ScsiStatus
                        if (scsi.spt.ScsiStatus != 0x02)
                        {
                            throw new NotSupportedException("SCSI Status != CheckCondition (Not Implemented)");
                        }
                        return SCSIStatusCodeName.CheckCondition;
                    }
                    else
                    {
                        // SCSI Sense == GOOD
                        if (scsi.spt.DataTransferLength > 0)
                        {
                            if (scsi.spt.DataIn == (byte)SCSIDataDirection.In)
                            {
                                response = new byte[scsi.spt.DataTransferLength];
                                Marshal.Copy(scsi.spt.DataBuffer, response, 0, response.Length);
                            }
                            else
                            {
                                response = new byte[0];
                            }
                            Log(Severity.Verbose, "Response Length: {0}", response.Length);

                            /*
                             * Intercept Inquiry and set peripherial device type.
                             * Currently only TAPE_DEVICE (0x01) and DISK_DEVICE (0x00) are supported.
                             * XXX: Should check only bits 0-4? See SPC-3 Standard INQUIRY data format
                             */
                            if (commandBytes[0] == (byte)SCSIOpCodeName.Inquiry)
                            {
                                UpdateLunDetails((byte)lun, response);
                            }

                            /*
                             * Intercept ModeSelect commands and quickly
                             * update the blocksize for future READ commands.
                             */
                            if (commandBytes[0] == (byte)SCSIOpCodeName.ModeSelect6 ||
                                commandBytes[0] == (byte)SCSIOpCodeName.ModeSelect10)
                            {
                                UpdateBlockSize((byte)lun);
                            }

                            return SCSIStatusCodeName.Good;
                        }
                        else
                        {
                            // SPTI request was GOOD, no data in response buffer.
                            return SCSIStatusCodeName.Good;
                        }
                    }
                }
            }
            finally
            {
                if (scsi != null && scsi.spt.DataBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(scsi.spt.DataBuffer);
                }

                if (inBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(inBuffer);
                }
            }
        }

        public void Log(Severity severity, string message)
        {
            // To be thread-safe we must capture the delegate reference first
            EventHandler<LogEntry> handler = OnLogEntry;
            if (handler != null)
            {
                handler(this, new LogEntry(DateTime.Now, severity, "SPTI Target", message));
            }
        }

        public void Log(Severity severity, string message, params object[] args)
        {
            Log(severity, String.Format(message, args));
        }

        private uint GetDataInTransferLength(byte[] commandBytes, byte lun)
        {
            switch ((SCSIOpCodeName)commandBytes[0])
            {
                case SCSIOpCodeName.Read16:                        // DATA_IN (12-14)
                case SCSIOpCodeName.ReadReverse16:                 // DATA_IN (12-14)
                case SCSIOpCodeName.Read6:                         // DATA_IN (2-4)
                case SCSIOpCodeName.ReadReverse6:                  // DATA_IN (2-4)
                case SCSIOpCodeName.Read10:                        // DATA_IN (7-8)
                case SCSIOpCodeName.Read12:                        // DATA_IN (6-9)
                    return GetReadTransferLength(commandBytes, lun);
                default:
                    return SCSICommandParser.GetCDBTransferLength(commandBytes, m_luns[lun].DeviceType);
            }
        }

        private uint GetReadTransferLength(byte[] commandBytes, byte lun)
        {
            if (m_luns[lun].BlockSizeIsSet == false)
            {
                UpdateBlockSize(lun);
                m_luns[lun].BlockSizeIsSet = true;
            }

            if (m_luns[lun].DeviceType == TAPE_DEVICE)
            {
                return SCSICommandParser.GetTapeReadTransferLength(commandBytes, m_luns[lun].BlockSize);
            }
            if (m_luns[lun].DeviceType == DISK_DEVICE)
            {
                return SCSICommandParser.GetDiskReadTransferLength(commandBytes, m_luns[lun].BlockSize);
            }
            throw new NotSupportedException("Device Type Not Supported!");
        }

        // Intercept Inquiry and update the peripheral deviceType
        private void UpdateLunDetails(byte lun, byte[] data)
        {
            m_luns[lun].DeviceType = data[0];
            Log(Severity.Verbose, "Lun: {0}, DeviceType Updated: {1}", lun, m_luns[lun].DeviceType);
        }

        // Send ModeSense and ReadCapacity to find READ command blockSize
        private void UpdateBlockSize(byte lun)
        {
            byte[] modeSenseCdb = new byte[] { 0x1A, 0x00, 0x10, 0x00, 0x20, 0x00 };
            byte[] readCapacityCdb = new byte[] { 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            if (m_luns[lun].DeviceType == TAPE_DEVICE)
            {
                // Send ModeSense6 (Device Configuration Page)
                byte[] response = new byte[32];
                if (SendSCSIDataInCmd(modeSenseCdb, lun, response, 32))
                {
                    /*
                     * Short LBA parameter block descriptor is meant for
                     * Direct Access Block Devices but the Logical Block Length
                     * uses the same bytes as the General-mode block descriptor
                     * Block Length
                     */
                    ShortLBAModeParameterBlockDescriptor parameter = new ShortLBAModeParameterBlockDescriptor(response, 0);
                    m_luns[lun].BlockSize = parameter.LogicalBlockLength;
                    Log(Severity.Verbose, "Tape BlockSize Updated: {0}", m_luns[lun].BlockSize);
                }
            }

            if (m_luns[lun].DeviceType == DISK_DEVICE)
            {
                // Send ReadCapacity10
                byte[] response = new byte[8];
                if (SendSCSIDataInCmd(readCapacityCdb, lun, response, 8))
                {
                    ReadCapacity10Parameter parameter = new ReadCapacity10Parameter(response);
                    m_luns[lun].BlockSize = parameter.BlockLengthInBytes;
                    Log(Severity.Verbose, "Disk BlockSize Updated: {0}", m_luns[lun].BlockSize);
                }
            }
        }

        // Secondary SPTI function used for updating blockSize
        private bool SendSCSIDataInCmd(byte[] commandBytes, byte lun, byte[] response, uint transferLength)
        {
            SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER scsi = null;
            IntPtr sptiBuffer = IntPtr.Zero;
            uint bytesReturned = 0;
            uint size = 0;
            bool rc = true;

            Array.Resize(ref commandBytes, 16);

            scsi = new SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER();
            scsi.spt.Cdb = commandBytes;
            scsi.spt.CdbLength = (byte)commandBytes.Length;
            scsi.spt.DataBuffer = Marshal.AllocHGlobal((int)transferLength);
            scsi.spt.DataIn = (byte)SCSIDataDirection.In;
            scsi.spt.DataTransferLength = transferLength;
            scsi.spt.Length = (short)Marshal.SizeOf(scsi.spt);
            scsi.spt.Lun = (byte)lun;
            scsi.spt.SenseInfoLength = (byte)scsi.sense.Length;
            scsi.spt.SenseInfoOffset = (uint)Marshal.OffsetOf(typeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER), "sense");
            scsi.spt.TimeOutValue = SCSI_TIMEOUT;

            sptiBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(scsi));
            Marshal.StructureToPtr(scsi, sptiBuffer, true);
            size = (uint)Marshal.SizeOf(scsi);

            if (!DeviceIoControl(m_handle, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                sptiBuffer, size, sptiBuffer, size, out bytesReturned, IntPtr.Zero))
            {
                int lastError = Marshal.GetLastWin32Error();
                Log(Severity.Error, "SendSCSICmd DeviceIoControl Error: {0}", lastError);
                rc = false;
            }
            else
            {
                Marshal.PtrToStructure(sptiBuffer, scsi);
                rc = (scsi.spt.ScsiStatus == 0x00) ? true : false;
                if (rc == false)
                {
                    Log(Severity.Verbose, "SendSCSIDataInCmd Sense: {0}", scsi.spt.ScsiStatus);
                }
            }

            if (scsi != null && scsi.spt.DataBuffer != IntPtr.Zero)
            {
                Marshal.Copy(scsi.spt.DataBuffer, response, 0, response.Length);
                Marshal.FreeHGlobal(scsi.spt.DataBuffer);
            }

            if (sptiBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(sptiBuffer);
            }

            return rc;
        }

    }
}
