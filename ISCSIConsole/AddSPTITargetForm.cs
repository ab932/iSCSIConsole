﻿using DiskAccessLibrary;
using ISCSI.Server;
using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace ISCSIConsole
{
    public partial class AddSPTITargetForm : Form
    {
        public const string DefaultTargetIQN = "iqn.1991-05.com.microsoft";

        public static int m_targetNumber = 0;
        private List<DeviceInfo> m_devices = new List<DeviceInfo>();
        private ISCSITarget m_target;

        public AddSPTITargetForm()
        {
            InitializeComponent();
        }

        private void AddSPTITargetForm_Load(object sender, EventArgs e)
        {
            m_targetNumber++;
            txtTargetIQN.Text = String.Format("{0}:sptitarget{1}", DefaultTargetIQN, m_targetNumber);
            List<DeviceInfo> devices = GetSPTIDevices();
            for (int index = 0; index < devices.Count; index++)
            {
                AddDevice(devices[index]);
            }
            listDisks.AutoResizeColumns(ColumnHeaderAutoResizeStyle.ColumnContent);
        }

        public static List<DeviceInfo> GetSPTIDevices()
        {
            List<DeviceInfo> result = new List<DeviceInfo>();
            List<DeviceInfo> tapeDeviceList = DeviceInterfaceUtils.GetDeviceList(DeviceInterfaceUtils.TapeClassGuid);
            List<DeviceInfo> diskDeviceList = DeviceInterfaceUtils.GetDeviceList(DeviceInterfaceUtils.DiskClassGuid);
            List<DeviceInfo> mediumChangerDeviceList = DeviceInterfaceUtils.GetDeviceList(DeviceInterfaceUtils.MediumChangerClassGuid);
            List<DeviceInfo> storagePortDeviceList = DeviceInterfaceUtils.GetDeviceList(DeviceInterfaceUtils.StoragePortClassGuid);
            result.AddRange(tapeDeviceList);
            result.AddRange(diskDeviceList);
            result.AddRange(mediumChangerDeviceList);
            result.AddRange(storagePortDeviceList);
            return result;
        }

        private void AddDevice(DeviceInfo device)
        {
            string description = device.DeviceDescription;
            string path = device.DevicePath;

            ListViewItem item = new ListViewItem(description);
            item.SubItems.Add(path);
            item.Tag = device;
            listDisks.Items.Add(item);
            m_devices.Add(device);
        }

        private void btnAddDevice_Click(object sender, EventArgs e)
        {
            if (!ISCSINameHelper.IsValidIQN(txtTargetIQN.Text))
            {
                MessageBox.Show("Target IQN is invalid", "Error");
                return;
            }

            if (listDisks.SelectedIndices.Count == 0)
            {
                MessageBox.Show("No device was selected", "Error");
                return;
            }
            int selectedIndex = listDisks.SelectedIndices[0];
            m_target = new ISCSITarget(txtTargetIQN.Text, m_devices[selectedIndex].DevicePath);
            this.DialogResult = DialogResult.OK;
            this.Close();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            m_targetNumber--;
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        private void btnRemove_Click(object sender, EventArgs e)
        {
            if (listDisks.SelectedIndices.Count > 0)
            {
                int selectedIndex = listDisks.SelectedIndices[0];
                m_devices.RemoveAt(selectedIndex);
                listDisks.Items.RemoveAt(selectedIndex);
            }
        }

        public ISCSITarget Target
        {
            get
            {
                return m_target;
            }
        }
    }
}
