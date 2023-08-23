using p5rpc.levelCap.Configuration;
using p5rpc.levelCap.Template;
using p5rpc.lib.interfaces;
using Reloaded.Hooks.Definitions;
using Reloaded.Hooks.Definitions.Enums;
using Reloaded.Hooks.Definitions.X64;
using Reloaded.Hooks.ReloadedII.Interfaces;
using Reloaded.Memory.SigScan.ReloadedII.Interfaces;
using Reloaded.Mod.Interfaces;
using System.Diagnostics;
using static p5rpc.lib.interfaces.Enums;
using IReloadedHooks = Reloaded.Hooks.ReloadedII.Interfaces.IReloadedHooks;

namespace p5rpc.levelCap
{
    /// <summary>
    /// Your mod logic goes here.
    /// </summary>
    public class Mod : ModBase // <= Do not Remove.
    {
        /// <summary>
        /// Provides access to the mod loader API.
        /// </summary>
        private readonly IModLoader _modLoader;

        /// <summary>
        /// Provides access to the Reloaded.Hooks API.
        /// </summary>
        /// <remarks>This is null if you remove dependency on Reloaded.SharedLib.Hooks in your mod.</remarks>
        private readonly IReloadedHooks? _hooks;

        /// <summary>
        /// Provides access to the Reloaded logger.
        /// </summary>
        private readonly ILogger _logger;

        /// <summary>
        /// Entry point into the mod, instance that created this class.
        /// </summary>
        private readonly IMod _owner;

        /// <summary>
        /// Provides access to this mod's configuration.
        /// </summary>
        private Config _configuration;

        /// <summary>
        /// The configuration of the currently executing mod.
        /// </summary>
        private readonly IModConfig _modConfig;

        private IFlowCaller _flowCaller;

        private IReverseWrapper<ShouldCapLevelDelegate> _shouldCapLevelReverseWrapper;

        private IAsmHook _jokerLevelCap;
        private IAsmHook _partyLevelCap;
        public Mod(ModContext context)
        {
            _modLoader = context.ModLoader;
            _hooks = context.Hooks;
            _logger = context.Logger;
            _owner = context.Owner;
            _configuration = context.Configuration;
            _modConfig = context.ModConfig;

            Utils.Initialise(_logger, _configuration);

            var startupScannerController = _modLoader.GetController<IStartupScanner>();
            if (startupScannerController == null || !startupScannerController.TryGetTarget(out var startupScanner))
            {
                Utils.LogError($"Unable to get controller for Reloaded SigScan Library, aborting initialisation");
                return;
            }

            var p5rLibController = _modLoader.GetController<IP5RLib>();
            if (p5rLibController == null || !p5rLibController.TryGetTarget(out var p5rLib))
            {
                Utils.LogError($"Unable to get controller for P5R Lib, aborting initialisation");
                return;
            }
            _flowCaller = p5rLib.FlowCaller;

            string shouldCapCall = _hooks.Utilities.GetAbsoluteCallMnemonics(ShouldCapLevel, out _shouldCapLevelReverseWrapper);

            startupScanner.AddMainModuleScan("03 59 ?? 48 8D 15 ?? ?? ?? ?? B9 01 00 00 00", result =>
            {
                if(!result.Found)
                {
                    Utils.LogError($"Unable to find address for Joker exp gain, his level will not be capped :(");
                    return;
                }
                Utils.LogDebug($"Found Joker exp gain at 0x{Utils.BaseAddress + result.Offset:X}");

                var levelAddress = Utils.GetGlobalAddress((nuint)Utils.BaseAddress + (nuint)result.Offset - 7) - 4;
                Utils.LogDebug($"Joker's level is at 0x{levelAddress:X}");
                
                string[] function =
                {
                    "use64",
                    "push rax",
                    $"{Utils.PushXmm(0)}\n{Utils.PushXmm(1)}\n{Utils.PushXmm(2)}\n{Utils.PushXmm(3)}",
                    "push r8 \npush r9 \npush r10 \npush r11",
                    "push rcx",
                    "push rdx",
                    $"mov rcx, [qword {_hooks.Utilities.WritePointer((nint)levelAddress)}]", // Write a pointer to the level since it's too far away
                    $"mov rcx, [rcx]", // Put Joker's level in rcx
                    "sub rsp, 40", // Make shadow space
                    $"{shouldCapCall}", // Call our function
                    "add rsp, 40", // Restore stack
                    "pop rdx",
                    "pop rcx",
                    "pop r11 \npop r10 \npop r9 \npop r8",
                    $"{Utils.PopXmm(3)}\n{Utils.PopXmm(2)}\n{Utils.PopXmm(1)}\n{Utils.PopXmm(0)}",
                    "pop rax",
                    "cmp rax, 0", // Check if we should cap
                    "je endHook", // If we shouldn't cap skip the subtraction
                    "sub ebx, dword [rcx + 4]", // Remove the gained exp
                    "label endHook",
                };

                _jokerLevelCap = _hooks.CreateAsmHook(function, Utils.BaseAddress + result.Offset, AsmHookBehaviour.ExecuteAfter).Activate();
            });

            startupScanner.AddMainModuleScan("48 C1 E2 04 46 01 54 ?? ??", result =>
            {
                if (!result.Found)
                {
                    Utils.LogError($"Unable to find address for Party exp gain, their levels will not be capped :(");
                    return;
                }
                Utils.LogDebug($"Found party exp gain at 0x{Utils.BaseAddress + result.Offset:X}");

                string[] function =
                {
                    "use64",
                    "push r8 \npush r9 \npush r10 \npush r11",
                    "push rcx",
                    "push rax",
                    "push rdx",
                    "mov rcx, [rdx+r8+0x48]", // Move the party member's level into rcx
                    "sub rsp, 40", // Make shadow space
                    $"{shouldCapCall}",
                    "add rsp, 40", // Make shadow space
                    "cmp rax, 0", // Check if we should cap
                    "pop rdx",
                    "pop rax",
                    "pop rcx",
                    "pop r11 \npop r10 \npop r9 \npop r8",
                    "je endHook",
                    "mov r10d, 0", // Set the gained exp to 0
                    "label endHook"
                };

                _partyLevelCap = _hooks.CreateAsmHook(function, Utils.BaseAddress + result.Offset, AsmHookBehaviour.ExecuteFirst).Activate();
            });

        }

        private bool ShouldCapLevel(short level)
        {
            Utils.LogDebug($"Level is {level}");
            bool doCap = false;
            if (_flowCaller.CHK_DAYS_STARTEND(4, 11, 5, 15) == 1)
            {
                Utils.Log("Kamoshida Date");
                if (level >= 15)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(5, 0x10, 6, 19) == 1)
            {
                Utils.Log("Madarame Date");
                if (level >= 25)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(6, 20, 7, 24) == 1)
            {
                Utils.Log("Kaneshiro Date");
                if (level >= 35)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(7, 25, 9, 14) == 1)
            {
                Utils.Log("Futaba Date");
                if (level >= 45)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(9, 15, 10, 10) == 1)
            {
                Utils.Log("Okumura Date");
                if (level >= 55)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(10, 11, 11, 23) == 1)
            {
                Utils.Log("Nijima Date");
                if (level >= 65)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(11, 24, 12, 14) == 1)
            {
                Utils.Log("Shido Date");
                if (level >= 75)
                {
                    doCap = true;
                }
            }
            else if (_flowCaller.CHK_DAYS_STARTEND(12, 15, 12, 24) == 1)
            {
                Utils.Log("Depth of Mementos Date");
                if (level >= 85)
                {
                    doCap = true;
                }
            }
            
            if (doCap)
            {
                Utils.LogDebug("Capping level");
            }
            
            return doCap;
        }

        [Function(CallingConventions.Microsoft)]
        private delegate bool ShouldCapLevelDelegate(short level);

        #region Standard Overrides
        public override void ConfigurationUpdated(Config configuration)
        {
            // Apply settings from configuration.
            // ... your code here.
            _configuration = configuration;
            _logger.WriteLine($"[{_modConfig.ModId}] Config Updated: Applying");
        }
        #endregion

        #region For Exports, Serialization etc.
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
        public Mod() { }
#pragma warning restore CS8618
        #endregion
    }
}