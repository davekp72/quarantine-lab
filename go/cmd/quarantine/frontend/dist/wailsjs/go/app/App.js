export function CompareSnapshotsJSON(from, to, refresh, excludeNoise) {
  return window.go.app.App.CompareSnapshotsJSON(from, to, refresh, excludeNoise);
}
export function GetVMStatusWails() {
  return window.go.app.App.GetVMStatusWails();
}
export function BuildFileTreeWails(json) {
  return window.go.app.App.BuildFileTreeWails(json);
}
export function BuildRegistryTreeWails(json) {
  return window.go.app.App.BuildRegistryTreeWails(json);
}
export function ReadSnapshotFileWails(snap, path) {
  return window.go.app.App.ReadSnapshotFileWails(snap, path);
}
export function DiffSnapshotFileWails(fromSnap, toSnap, path) {
  return window.go.app.App.DiffSnapshotFileWails(fromSnap, toSnap, path);
}
export function ExportSnapshotFileWails(snapshotName, guestPath) {
  return window.go.app.App.ExportSnapshotFileWails(snapshotName, guestPath);
}
export function ExportPcapWails(snapshotName) {
  return window.go.app.App.ExportPcapWails(snapshotName);
}
export function LoadDiffFile(path) {
  return window.go.app.App.LoadDiffFile(path);
}
export function ListSnapshotsWails() {
  return window.go.app.App.ListSnapshotsWails();
}
export function TakeSnapshotWails(name, description, force) {
  return window.go.app.App.TakeSnapshotWails(name, description, force);
}
export function PreserveEvidenceWails(label, stopCapture) {
  return window.go.app.App.PreserveEvidenceWails(label, stopCapture);
}
export function ResetToSnapshotWails(name, clean) {
  return window.go.app.App.ResetToSnapshotWails(name, clean);
}
export function LaunchSnapshotWails(name, clean) {
  return window.go.app.App.LaunchSnapshotWails(name, clean);
}
export function DeleteSnapshotWails(name, force) {
  return window.go.app.App.DeleteSnapshotWails(name, force);
}
export function GetAppLogWails() {
  return window.go.app.App.GetAppLogWails();
}
export function GetAppLogFilteredWails(minLevel) {
  return window.go.app.App.GetAppLogFilteredWails(minLevel);
}
export function ClearAppLogWails() {
  return window.go.app.App.ClearAppLogWails();
}
export function ListLogFilesWails() {
  return window.go.app.App.ListLogFilesWails();
}
export function TailLogFileWails(path, maxLines) {
  return window.go.app.App.TailLogFileWails(path, maxLines);
}
export function CaptureStatusWails() {
  return window.go.app.App.CaptureStatusWails();
}
export function StartCaptureWails() {
  return window.go.app.App.StartCaptureWails();
}
export function StopCaptureWails() {
  return window.go.app.App.StopCaptureWails();
}
export function DecodeHTTPBodyWails(encoding, contentEncoding, body) {
  return window.go.app.App.DecodeHTTPBodyWails(encoding, contentEncoding, body);
}
export function InspectPcapFlowWails(snapshotName, flowID, format) {
  return window.go.app.App.InspectPcapFlowWails(snapshotName, flowID, format);
}
export function ListPcapFlowsWails(snapshotName) {
  return window.go.app.App.ListPcapFlowsWails(snapshotName);
}
export function GatewayStatusWails() {
  return window.go.app.App.GatewayStatusWails();
}
export function GatewayTrafficModeWails() {
  return window.go.app.App.GatewayTrafficModeWails();
}
export function SetGatewayTrafficModeWails(mode) {
  return window.go.app.App.SetGatewayTrafficModeWails(mode);
}
export function PermissivePolicyWails() {
  return window.go.app.App.PermissivePolicyWails();
}
export function SetPermissivePolicyWails(tcpPorts, udpPorts, forceDNS, allowICMP) {
  return window.go.app.App.SetPermissivePolicyWails(tcpPorts, udpPorts, forceDNS, allowICMP);
}
export function CheckHostPublicIPWails() {
  return window.go.app.App.CheckHostPublicIPWails();
}
export function ShouldWarnPublicIPBeforeLaunchWails() {
  return window.go.app.App.ShouldWarnPublicIPBeforeLaunchWails();
}
export function UISettingsWails() {
  return window.go.app.App.UISettingsWails();
}
export function SetUISettingsWails(filePreviewMaxKb, hideRoutineNoise, refreshOnCompare, warnPublicIP, homeIspPatterns, contentMaxKb, hashMaxMb, totalEmbedMaxMb) {
  return window.go.app.App.SetUISettingsWails(filePreviewMaxKb, hideRoutineNoise, refreshOnCompare, warnPublicIP, homeIspPatterns, contentMaxKb, hashMaxMb, totalEmbedMaxMb);
}
export function SetNoiseDomainsWails(text) {
  return window.go.app.App.SetNoiseDomainsWails(text);
}
export function SetNoiseFilesWails(text) {
  return window.go.app.App.SetNoiseFilesWails(text);
}
export function SetNoiseRegistryWails(text) {
  return window.go.app.App.SetNoiseRegistryWails(text);
}
export function ListCasesWails() {
  return window.go.app.App.ListCasesWails();
}
export function SaveCaseWails(excludeNoise) {
  return window.go.app.App.SaveCaseWails(excludeNoise);
}
export function LoadCaseWails(id) {
  return window.go.app.App.LoadCaseWails(id);
}
export function DeleteCaseWails(id) {
  return window.go.app.App.DeleteCaseWails(id);
}
export function ReadCaseFileWails(caseID, guestPath) {
  return window.go.app.App.ReadCaseFileWails(caseID, guestPath);
}
export function DiffCaseFileWails(caseID, guestPath) {
  return window.go.app.App.DiffCaseFileWails(caseID, guestPath);
}
export function ClearActiveCaseWails() {
  return window.go.app.App.ClearActiveCaseWails();
}
