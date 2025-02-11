import "pe"

rule MAL_WIN_Trojan_Qbot
{
    meta:
        description = "Detects qbot trojan attempting to emulate a GIMP dll"
        author="James Jolley"
        date="2024-04-09"
        reference = "https://redcanary.com/threat-detection-report/threats/qbot/"
        hash="6a8557a2f8e1338e6edb2a07c345882389230ea24ffeb741a59621b7e8b56c59"
	strings:
		$s1 = "Tdk_threads_mutex" 
		$s2 = "Tdk_window_process_all_updates" 
		$s3 = "Tdk_window_process_updates" 
		$s4 = "Tdk_spawn_command_line_on_screen" 
		$s5 = "Tdk_drag_context_list_targets" 
		$s6 = "Tdk_win32_selection_add_targets" 
		$s7 = "Tdk_utf8_to_string_target" 
		$s8 = "gdk_pango_renderer_set_drawable() and gdk_pango_renderer_set_drawable()must be used to set the target drawable and GC before usi" ascii
		$s9 = "Tdk_spawn_on_screen_with_pipes" 
		$s10 = "  VirtualQuery failed for %d bytes at address %p" 
		$s11 = "Tdk_device_get_key" 
		$s12 = "Tdk_screen_get_system_visual" 
		$s13 = "Tdk_window_get_root_coords" 
        $s14 = "AccessX_Enable"
		$s15 = "Tdk_window_get_user_data" 
		$s16 = "Tdk_window_get_root_origin" 
		$s17 = "Tdk_keymap_get_entries_for_keycode" 
		$s18 = "GIMP Drawing Kit" wide
        $s19 = "WACOM Tablet" wide
        $s20 = "gdkWindowTempShadow" wide
        $h1 = { 4D 5A }
    condition:
        pe.characteristics & pe.DLL and
        filesize < 1000KB and
        all of ($s*)
}   