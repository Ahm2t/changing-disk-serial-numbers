#include "stdafx.h"

/*


CREDITS TO BTBD FOR HIS HWID SPOOFER REPOSITORY IN GITHUB!



I HAVE ADDED SLIGHT ANTI PASTA CODE IN THIS SOURCE! IT WILL NOT WORK FOR KDMAPPER! (YOU NEED TO FIX A PROBLEM WHICH I ADDED BY PURPOSE)

*/







struct {
	DWORD Length;
	NIC_DRIVER Drivers[0xFF];
} NICs = { 0 };

PDRIVER_DISPATCH DiskControlOriginal = 0, MountControlOriginal = 0, PartControlOriginal = 0, NsiControlOriginal = 0, GpuControlOriginal = 0;

/**** DISKS ****/
NTSTATUS PartInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(PARTITION_INFORMATION_EX)) {
			PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.PartitionId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartLayoutIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX)) {
			PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
			if (PARTITION_STYLE_GPT == info->PartitionStyle) {
				memset(&info->Gpt.DiskId, 0, sizeof(GUID));
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS PartControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_DISK_GET_PARTITION_INFO_EX:
			ChangeIoc(ioc, irp, PartInfoIoc);
			break;
		case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
			ChangeIoc(ioc, irp, PartLayoutIoc);
			break;
	}

	return PartControlOriginal(device, irp);
}

NTSTATUS StorageQueryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
			ULONG offset = desc->SerialNumberOffset;
			if (offset && offset < request.BufferLength) {
				strcpy((PCHAR)desc + offset, SERIAL);

			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + sizeof(PIDENTIFY_DEVICE_DATA)) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (offset && offset < request.BufferLength) {
				PCHAR serial = (PCHAR)((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset))->SerialNumber;
				SwapEndianess(serial, SERIAL);

			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			PCHAR serial = ((PIDSECTOR)((PSENDCMDOUTPARAMS)request.Buffer)->bBuffer)->sSerialNumber;
			SwapEndianess(serial, SERIAL);

		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS DiskControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_STORAGE_QUERY_PROPERTY:
			if (StorageDeviceProperty == ((PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer)->PropertyId) {
				ChangeIoc(ioc, irp, StorageQueryIoc);
			}
			break;
		case IOCTL_ATA_PASS_THROUGH:
			ChangeIoc(ioc, irp, AtaPassIoc);
			break;
		case SMART_RCV_DRIVE_DATA:
			ChangeIoc(ioc, irp, SmartDataIoc);
			break;
	}

	return DiskControlOriginal(device, irp);
}



void readshitfile()
{
	//https://cdn.discordapp.com/attachments/735346053221711995/742657291420958750/unknown.png this shit is srs cringe lmfao

	UNICODE_STRING unicodename;
	OBJECT_ATTRIBUTES attributeobj;
	IO_STATUS_BLOCK ioStatusBlock;
	LARGE_INTEGER byteoffs;
	HANDLE handle;

	byteoffs.QuadPart = 0;

	//this shit reads file for serials btw!
	RtlInitUnicodeString(&unicodename, L"\\SystemRoot\\Cheating.Win - serial.tmp");

	InitializeObjectAttributes(&attributeobj, &unicodename, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);

	//i know im not supposed to be doing this shit with this irql level, since it can cause some srs shit, but whatever doing what that retard level skid did ¯\_(ツ)_/¯
	ZwCreateFile(&handle, GENERIC_ALL, &attributeobj, &ioStatusBlock, 0,FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

	//ik im reading 50 bytes of that file, so change as you will, but keep in mind exceeding a certain limit (i forgot), will cause an buffer overflow so dont read more than 50 bytes :p
	ZwReadFile(handle, 0, 0, 0, &ioStatusBlock, SERIAL, 50, &byteoffs, 0);
	
	//nulling out last character for ending
	SERIAL[49] = 0;

	//close the handle or bad things happen, and ur prob going to get nightmares for a while :P
	ZwClose(handle);
}


VOID SpoofDisks() {

	readshitfile();

	//how is this not dt by battle eye?
	UNICODE_STRING disk_str = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	PDRIVER_OBJECT disk_object = 0;

	NTSTATUS status = ObReferenceObjectByName(&disk_str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, &disk_object);
	if (!NT_SUCCESS(status)) {
		return;
	}

	AppendSwap(disk_str, &disk_object->MajorFunction[IRP_MJ_DEVICE_CONTROL], DiskControl, DiskControlOriginal);

	DISK_FAIL_PREDICTION DiskEnableDisableFailurePrediction = (DISK_FAIL_PREDICTION)FindPatternImage(disk_object->DriverStart, "\x48\x89\x00\x24\x10\x48\x89\x74\x24\x18\x57\x48\x81\xEC\x90\x00", "xx?xxxxxxxxxxxxx");
	if (DiskEnableDisableFailurePrediction) {
		ULONG length = 0;
		if (STATUS_BUFFER_TOO_SMALL == (status = IoEnumerateDeviceObjectList(disk_object, 0, 0, &length)) && length) {
			ULONG size = length * sizeof(PDEVICE_OBJECT);
			PDEVICE_OBJECT *devices = ExAllocatePool(NonPagedPool, size);
			if (devices) {
				if (NT_SUCCESS(status = IoEnumerateDeviceObjectList(disk_object, devices, size, &length)) && length) {
					ULONG success = 0, total = 0;

					for (ULONG i = 0; i < length; ++i) {
						PDEVICE_OBJECT device = devices[i];

						// Update disk properties for disk ID
						PDEVICE_OBJECT disk = IoGetAttachedDeviceReference(device);
						if (disk) {
							KEVENT event = { 0 };
							KeInitializeEvent(&event, NotificationEvent, FALSE);

							PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_DISK_UPDATE_PROPERTIES, disk, 0, 0, 0, 0, 0, &event, 0);
							if (irp) {
								if (STATUS_PENDING == IoCallDriver(disk, irp)) {
									KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
								}
							} else {
							}

							ObDereferenceObject(disk);
						}

						PFUNCTIONAL_DEVICE_EXTENSION ext = device->DeviceExtension;
						if (ext) {
							strcpy((PCHAR)ext->DeviceDescriptor + ext->DeviceDescriptor->SerialNumberOffset, SERIAL);

							// Disables SMART
							if (NT_SUCCESS(status = DiskEnableDisableFailurePrediction(ext, FALSE))) {
								++success;
							} else {
							}

							++total;
						}
						
						ObDereferenceObject(device);
					}

				} else {
				}

				ExFreePool(devices);
			} else {
			}
		} else {
		}
	} else {
	}

	ObDereferenceObject(disk_object);

}

/**** VOLUMES ****/
NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			for (DWORD i = 0; i < points->NumberOfMountPoints; ++i) {
				PMOUNTMGR_MOUNT_POINT point = &points->MountPoints[i];
				if (point->UniqueIdOffset) {
					point->UniqueIdLength = 0;
				}

				if (point->SymbolicLinkNameOffset) {
					point->SymbolicLinkNameLength = 0;
				}
			}
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			((PMOUNTDEV_UNIQUE_ID)request.Buffer)->UniqueIdLength = 0;
		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS MountControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_MOUNTMGR_QUERY_POINTS:
			ChangeIoc(ioc, irp, MountPointsIoc);
			break;
		case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
			ChangeIoc(ioc, irp, MountUniqueIoc);
			break;
	}

	return MountControlOriginal(device, irp);
}

// Volume serial is spoofed from usermode
void SpoofVolumes() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\mountmgr"), MountControl, MountControlOriginal);
}

/**** NIC ****/
NTSTATUS NICIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		IOC_REQUEST request = *(PIOC_REQUEST)context;
		ExFreePool(context);

		if (irp->MdlAddress) {
			SpoofBuffer(SEED, (PBYTE)MmGetSystemAddressForMdl(irp->MdlAddress), 6);

		}

		if (request.OldRoutine && irp->StackCount > 1) {
			return request.OldRoutine(device, irp, request.OldContext);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NICControl(PDEVICE_OBJECT device, PIRP irp) {
	for (DWORD i = 0; i < NICs.Length; ++i) {
		PNIC_DRIVER driver = &NICs.Drivers[i];

		if (driver->Original && driver->DriverObject == device->DriverObject) {
			PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
			switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
				case IOCTL_NDIS_QUERY_GLOBAL_STATS: {
					switch (*(PDWORD)irp->AssociatedIrp.SystemBuffer) {
						case OID_802_3_PERMANENT_ADDRESS:
						case OID_802_3_CURRENT_ADDRESS:
						case OID_802_5_PERMANENT_ADDRESS:
						case OID_802_5_CURRENT_ADDRESS:
							ChangeIoc(ioc, irp, NICIoc);
							break;
					}

					break;
				}
			}

			return driver->Original(device, irp);
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS NsiControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_NSI_PROXY_ARP: {
			DWORD length = ioc->Parameters.DeviceIoControl.OutputBufferLength;
			NTSTATUS ret = NsiControlOriginal(device, irp);

			PNSI_PARAMS params = (PNSI_PARAMS)irp->UserBuffer;
			if (params && NSI_PARAMS_ARP == params->Type) {
				memset(irp->UserBuffer, 0, length);

			}

			return ret;
		}
	}

	return NsiControlOriginal(device, irp);
}

VOID SpoofNIC() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy"), NsiControl, NsiControlOriginal);

	PVOID base = GetBaseAddress("ndis.sys", 0);
	if (!base) {
		return;
	}

	PNDIS_FILTER_BLOCK ndisGlobalFilterList = FindPatternImage(base, "\x40\x8A\xF0\x48\x8B\x05", "xxxxxx");
	if (ndisGlobalFilterList) {
		PDWORD ndisFilter_IfBlock = FindPatternImage(base, "\x48\x85\x00\x0F\x84\x00\x00\x00\x00\x00\x8B\x00\x00\x00\x00\x00\x33", "xx?xx?????x???xxx");
		if (ndisFilter_IfBlock) {
			DWORD ndisFilter_IfBlock_offset = *(PDWORD)((PBYTE)ndisFilter_IfBlock + 12);

			ndisGlobalFilterList = (PNDIS_FILTER_BLOCK)((PBYTE)ndisGlobalFilterList + 3);
			ndisGlobalFilterList = *(PNDIS_FILTER_BLOCK *)((PBYTE)ndisGlobalFilterList + 7 + *(PINT)((PBYTE)ndisGlobalFilterList + 3));

			DWORD count = 0;
			for (PNDIS_FILTER_BLOCK filter = ndisGlobalFilterList; filter; filter = filter->NextFilter) {
				PNDIS_IF_BLOCK block = *(PNDIS_IF_BLOCK *)((PBYTE)filter + ndisFilter_IfBlock_offset);
				if (block) {
					PWCHAR copy = SafeCopy(filter->FilterInstanceName->Buffer, MAX_PATH);
					if (copy) {
						WCHAR adapter[MAX_PATH] = { 0 };
						swprintf(adapter, L"\\Device\\%ws", TrimGUID(copy, MAX_PATH / 2));
						ExFreePool(copy);


						UNICODE_STRING name = { 0 };
						RtlInitUnicodeString(&name, adapter);

						PFILE_OBJECT file = 0;
						PDEVICE_OBJECT device = 0;

						NTSTATUS status = IoGetDeviceObjectPointer(&name, FILE_READ_DATA, &file, &device);
						if (NT_SUCCESS(status)) {
							PDRIVER_OBJECT driver = device->DriverObject;
							if (driver) {
								BOOL exists = FALSE;
								for (DWORD i = 0; i < NICs.Length; ++i) {
									if (NICs.Drivers[i].DriverObject == driver) {
										exists = TRUE;
										break;
									}
								}

								if (exists) {
								} else {
									PNIC_DRIVER nic = &NICs.Drivers[NICs.Length];
									nic->DriverObject = driver;

									AppendSwap(driver->DriverName, &driver->MajorFunction[IRP_MJ_DEVICE_CONTROL], NICControl, nic->Original);

									++NICs.Length;
								}
							}

							// Indirectly dereferences device object
							ObDereferenceObject(file);
						} else {
						}
					}

					// Current MAC
					PIF_PHYSICAL_ADDRESS_LH addr = &block->ifPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);
					addr = &block->PermanentPhysAddress;
					SpoofBuffer(SEED, addr->Address, addr->Length);

					++count;
				}
			}

		} else {
		}
	} else {
	}
}

/**** SMBIOS (and boot) ****/
void SpoofSMBIOS() {
	PVOID base = GetBaseAddress("ntoskrnl.exe", 0);
	if (!base) {
		return;
	}

	PBYTE ExpBootEnvironmentInformation = FindPatternImage(base, "\x0F\x10\x05\x00\x00\x00\x00\x0F\x11\x00\x8B", "xxx????xx?x");
	if (ExpBootEnvironmentInformation) {
		ExpBootEnvironmentInformation = ExpBootEnvironmentInformation + 7 + *(PINT)(ExpBootEnvironmentInformation + 3);
		SpoofBuffer(SEED, ExpBootEnvironmentInformation, 16);

	} else {
	}

	PPHYSICAL_ADDRESS WmipSMBiosTablePhysicalAddress = FindPatternImage(base, "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15", "xxx????xxxx?xx");
	if (WmipSMBiosTablePhysicalAddress) {
		WmipSMBiosTablePhysicalAddress = (PPHYSICAL_ADDRESS)((PBYTE)WmipSMBiosTablePhysicalAddress + 7 + *(PINT)((PBYTE)WmipSMBiosTablePhysicalAddress + 3));
		memset(WmipSMBiosTablePhysicalAddress, 0, sizeof(PHYSICAL_ADDRESS));

	} else {
	}
}

/**** GPU ****/
NTSTATUS GpuControl(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	switch (ioc->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_NVIDIA_SMIL: {
			NTSTATUS ret = GpuControlOriginal(device, irp);

			PCHAR buffer = irp->UserBuffer;
			if (buffer) {
				PCHAR copy = SafeCopy(buffer, IOCTL_NVIDIA_SMIL_MAX);
				if (copy) {
					for (DWORD i = 0; i < IOCTL_NVIDIA_SMIL_MAX - 4; ++i) {
						if (0 == memcmp(copy + i, "GPU-", 4)) {
							buffer[i] = 0;

							break;
						}
					}

					ExFreePool(copy);
				}
			}

			return ret;
		}
	}

	return GpuControlOriginal(device, irp);
}

VOID SpoofGPU() {
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nvlddmkm"), GpuControl, GpuControlOriginal);
}

NTSTATUS IoCreateDriver(PUNICODE_STRING, PDRIVER_INITIALIZE);

NTSTATUS Entrypoint(PDRIVER_OBJECT driver, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);
	UNREFERENCED_PARAMETER(driver);

	ULONG64 time = 0;
	KeQuerySystemTime(&time);
	SEED = (DWORD)time;

	SpoofDisks();
	SpoofVolumes();
	SpoofNIC();
	SpoofSMBIOS();
	SpoofGPU();

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {
	return IoCreateDriver(0, &Entrypoint);
}