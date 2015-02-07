﻿// Copyright © 2011 - Present RealDimensions Software, LLC
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 
// You may obtain a copy of the License at
// 
// 	http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace chocolatey.infrastructure.app.services
{
    using System;
    using System.Collections.Concurrent;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using commandline;
    using configuration;
    using domain;
    using filesystem;
    using infrastructure.services;
    using logging;
    using platforms;
    using results;

    public class ChocolateyPackageService : IChocolateyPackageService
    {
        private readonly INugetService _nugetService;
        private readonly IEnumerable<ISourceRunner> _sourceRunners;
        private readonly IPowershellService _powershellService;
        private readonly IShimGenerationService _shimgenService;
        private readonly IFileSystem _fileSystem;
        private readonly IRegistryService _registryService;
        private readonly IChocolateyPackageInformationService _packageInfoService;
        private readonly IAutomaticUninstallerService _autoUninstallerService;
        private readonly IXmlService _xmlService;

        public ChocolateyPackageService(INugetService nugetService, IPowershellService powershellService, IShimGenerationService shimgenService, IFileSystem fileSystem, IRegistryService registryService, IChocolateyPackageInformationService packageInfoService, IAutomaticUninstallerService autoUninstallerService, IXmlService xmlService)
        {
            _nugetService = nugetService;
            _sourceRunners = sourceRunners;
            _powershellService = powershellService;
            _shimgenService = shimgenService;
            _fileSystem = fileSystem;
            _registryService = registryService;
            _packageInfoService = packageInfoService;
            _autoUninstallerService = autoUninstallerService;
            _xmlService = xmlService;
        }

        public void ensure_source_app_installed(ChocolateyConfiguration config)
        {
            perform_source_runner_action(config, r => r.ensure_source_app_installed(config, (packageResult) => handle_package_result(packageResult, config, CommandNameType.install)));
        }

        private void perform_source_runner_action(ChocolateyConfiguration config, Action<ISourceRunner> action)
        {
            var runner = _sourceRunners.FirstOrDefault(r => r.SourceType == config.SourceType);
            if (runner != null && action != null)
            {
                action.Invoke(runner);
            }
            else
            {
                this.Log().Warn("No runner was found that implements source type '{0}' or action was missing".format_with(config.SourceType.to_string()));
            }
        }

        private T perform_source_runner_function<T>(ChocolateyConfiguration config, Func<ISourceRunner, T> function)
        {
            var runner = _sourceRunners.FirstOrDefault(r => r.SourceType == config.SourceType);
            if (runner != null && function != null)
            {
                return function.Invoke(runner);
            }

            this.Log().Warn("No runner was found that implements source type '{0}' or function was missing.".format_with(config.SourceType.to_string()));
            return default(T);
        }

        public void list_noop(ChocolateyConfiguration config)
        {
            perform_source_runner_action(config, r => r.list_noop(config));
        }

        public void list_run(ChocolateyConfiguration config, bool logResults)
        {
            this.Log().Debug(() => "Searching for package information");

            var list = perform_source_runner_function(config, r => r.list_run(config, logResults));

            if (config.SourceType == SourceType.normal)
            {
                if (config.RegularOuptut)
                {
                    this.Log().Warn(() => @"{0} packages {1}.".format_with(list.Count, config.ListCommand.LocalOnly ? "installed" : "found"));

                    if (config.ListCommand.LocalOnly && config.ListCommand.IncludeRegistryPrograms)
                    {
                        report_registry_programs(config, list);
                    }
                }
            }
        }

        private void report_registry_programs(ChocolateyConfiguration config, ConcurrentDictionary<string, PackageResult> list)
        {
            var itemsToRemoveFromMachine = new List<string>();
            foreach (var packageResult in list)
            {
                if (packageResult.Value != null && packageResult.Value.Package != null)
                {
                    var pkginfo = _packageInfoService.get_package_information(packageResult.Value.Package);
                    if (pkginfo.RegistrySnapshot == null)
                    {
                        continue;
                    }
                    var key = pkginfo.RegistrySnapshot.RegistryKeys.FirstOrDefault();
                    if (key != null)
                    {
                        itemsToRemoveFromMachine.Add(key.DisplayName);
                    }
                }
            }
            var machineInstalled = _registryService.get_installer_keys().RegistryKeys.Where((p) => p.is_in_programs_and_features() && !itemsToRemoveFromMachine.Contains(p.DisplayName)).OrderBy((p) => p.DisplayName).Distinct().ToList();
            if (machineInstalled.Count != 0)
            {
                this.Log().Info(() => "");
                foreach (var key in machineInstalled.or_empty_list_if_null())
                {
                    this.Log().Info("{0}|{1}".format_with(key.DisplayName, key.DisplayVersion));
                    if (config.Verbose) this.Log().Info(" InstallLocation: {0}{1} Uninstall:{2}".format_with(key.InstallLocation.escape_curly_braces(), Environment.NewLine, key.UninstallString.escape_curly_braces()));
                }
                this.Log().Warn(() => @"{0} applications not managed with Chocolatey.".format_with(machineInstalled.Count));
            }
        }

        public void pack_noop(ChocolateyConfiguration config)
        {
            if (config.SourceType != SourceType.normal)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "This source doesn't provide a facility for packaging.");
                return;
            }

            _nugetService.pack_noop(config);
        }

        public void pack_run(ChocolateyConfiguration config)
        {
            if (config.SourceType != SourceType.normal)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "This source doesn't provide a facility for packaging.");
                return;
            }

            _nugetService.pack_run(config);
        }

        public void push_noop(ChocolateyConfiguration config)
        {
            if (config.SourceType != SourceType.normal)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "This source doesn't provide a facility for pushing.");
                return;
            }

            _nugetService.push_noop(config);
        }

        public void push_run(ChocolateyConfiguration config)
        {
            if (config.SourceType != SourceType.normal)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "This source doesn't provide a facility for pushing.");
                return;
            }

            _nugetService.push_run(config);
        }

        public void install_noop(ChocolateyConfiguration config)
        {
            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
                action = (pkg) => _powershellService.install_noop(pkg);
            }
            
            perform_source_runner_action(config, r => r.install_noop(config, action));
        }

        public ConcurrentDictionary<string, PackageResult> install_run(ChocolateyConfiguration config)
        {
            //todo:are we installing from an alternate source? If so run that command instead

            this.Log().Info(@"Installing the following packages:");
            this.Log().Info(ChocolateyLoggers.Important, @"{0}".format_with(config.PackageNames));
            this.Log().Info(@"By installing you accept licenses for the packages.");

            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
                action = (packageResult) => handle_package_result(packageResult, config, CommandNameType.install);
            }

            var packageInstalls = new ConcurrentDictionary<string, PackageResult>();

            foreach (var packageConfig in set_config_from_package_names_and_packages_config(config, packageInstalls).or_empty_list_if_null())
            {
               var results =  perform_source_runner_function(packageConfig, r => r.install_run(packageConfig, action));
                foreach (var result in results)
                {
                    packageInstalls.GetOrAdd(result.Key, result.Value);
                }
            }

            var installFailures = packageInstalls.Count(p => !p.Value.Success);
            var installWarnings = packageInstalls.Count(p => p.Value.Warning);
            this.Log().Warn(() => @"{0}{1} installed {2}/{3} package(s). {4} package(s) failed.{5}{0} See the log for details.".format_with(
                Environment.NewLine,
                ApplicationParameters.Name,
                packageInstalls.Count(p => p.Value.Success && !p.Value.Inconclusive),
                packageInstalls.Count,
                installFailures,
                installWarnings == 0 ? string.Empty : "{0} {1} package(s) had warnings.".format_with(Environment.NewLine, installWarnings)));

            if (installWarnings != 0)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "Warnings:");
                foreach (var warning in packageInstalls.Where(p => p.Value.Warning).or_empty_list_if_null())
                {
                    this.Log().Warn(ChocolateyLoggers.Important, " - {0}".format_with(warning.Value.Name));
                }
            }

            if (installFailures != 0)
            {
                this.Log().Error("Failures:");
                foreach (var failure in packageInstalls.Where(p => !p.Value.Success).or_empty_list_if_null())
                {
                    this.Log().Error(" - {0}".format_with(failure.Value.Name));
                }
            }

            if (installFailures != 0 && Environment.ExitCode == 0)
            {
                Environment.ExitCode = 1;
            }

            return packageInstalls;
        }


        public void upgrade_noop(ChocolateyConfiguration config)
        {
            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
                action = (pkg) => _powershellService.install_noop(pkg);
            }

            var noopUpgrades = perform_source_runner_function(config, r => r.upgrade_noop(config, action));
            if (config.RegularOuptut)
            {
                this.Log().Warn(() => @"{0}There are {1} packages available for upgrade.{0} See the log for details.".format_with(
                Environment.NewLine,
                noopUpgrades.Count));
            }
        }

        public ConcurrentDictionary<string, PackageResult> upgrade_run(ChocolateyConfiguration config)
        {
            //todo:are we upgrading an alternate source? If so run that command instead

            this.Log().Info(@"Upgrading the following packages:");
            this.Log().Info(ChocolateyLoggers.Important, @"{0}".format_with(config.PackageNames));
            this.Log().Info(@"By installing you accept licenses for the packages.");

            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
                action =  (packageResult) => handle_package_result(packageResult, config, CommandNameType.upgrade);
            }

            var packageUpgrades = perform_source_runner_function(config, r => r.upgrade_run(config, action));
            
            var upgradeFailures = packageUpgrades.Count(p => !p.Value.Success);
            var upgradeWarnings = packageUpgrades.Count(p => p.Value.Warning);
            this.Log().Warn(() => @"{0}{1} upgraded {2}/{3} package(s). {4} package(s) failed.{5}{0} See the log for details.".format_with(
                Environment.NewLine,
                ApplicationParameters.Name,
                packageUpgrades.Count(p => p.Value.Success && !p.Value.Inconclusive),
                packageUpgrades.Count,
                upgradeFailures,
                upgradeWarnings == 0 ? string.Empty : "{0} {1} package(s) had warnings.".format_with(Environment.NewLine, upgradeWarnings)));

            if (upgradeWarnings != 0)
            {
                this.Log().Warn(ChocolateyLoggers.Important, "Warnings:");
                foreach (var warning in packageUpgrades.Where(p => p.Value.Warning).or_empty_list_if_null())
                {
                    this.Log().Warn(ChocolateyLoggers.Important, " - {0}".format_with(warning.Value.Name));
                }
            }

            if (upgradeFailures != 0)
            {
                this.Log().Error("Failures:");
                foreach (var failure in packageUpgrades.Where(p => !p.Value.Success).or_empty_list_if_null())
                {
                    this.Log().Error(" - {0}".format_with(failure.Value.Name));
                }
            }

            if (upgradeFailures != 0 && Environment.ExitCode == 0)
            {
                Environment.ExitCode = 1;
            }

            return packageUpgrades;
        }

        public void uninstall_noop(ChocolateyConfiguration config)
        {
            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
            _nugetService.install_noop(config, (pkg) => _powershellService.install_noop(pkg));
            }

            perform_source_runner_action(config, r => r.uninstall_noop(config, action));
        }

        public ConcurrentDictionary<string, PackageResult> uninstall_run(ChocolateyConfiguration config)
        {
            this.Log().Info(@"Uninstalling the following packages:");
            this.Log().Info(ChocolateyLoggers.Important, @"{0}".format_with(config.PackageNames));

            Action<PackageResult> action = null;
            if (config.SourceType == SourceType.normal)
            {
                action = (packageResult) => handle_package_uninstall(packageResult, config);
            }

            var packageUninstalls = perform_source_runner_function(config, r => r.uninstall_run(config, action));

            var uninstallFailures = packageUninstalls.Count(p => !p.Value.Success);
            this.Log().Warn(() => @"{0}{1} uninstalled {2}/{3} packages. {4} packages failed.{0}See the log for details.".format_with(
                Environment.NewLine,
                ApplicationParameters.Name,
                packageUninstalls.Count(p => p.Value.Success && !p.Value.Inconclusive),
                packageUninstalls.Count,
                uninstallFailures));

            if (uninstallFailures != 0)
            {
                this.Log().Error("Failures");
                foreach (var failure in packageUninstalls.Where(p => !p.Value.Success).or_empty_list_if_null())
                {
                    this.Log().Error(" - {0}".format_with(failure.Value.Name));
                }
            }

            if (uninstallFailures != 0 && Environment.ExitCode == 0)
            {
                Environment.ExitCode = 1;
            }

            return packageUninstalls;
        }

        public void handle_package_result(PackageResult packageResult, ChocolateyConfiguration config, CommandNameType commandName)
        {
            var pkgInfo = _packageInfoService.get_package_information(packageResult.Package);
            if (config.AllowMultipleVersions)
            {
                pkgInfo.IsSideBySide = true;
            }

            if (config.Information.PlatformType == PlatformType.Windows)
            {
                if (!config.SkipPackageInstallProvider)
                {
                    var before = _registryService.get_installer_keys();

                    var powerShellRan = _powershellService.install(config, packageResult);
                    if (powerShellRan)
                    {
                        //todo: prevent reboots
                    }

                    var difference = _registryService.get_differences(before, _registryService.get_installer_keys());
                    if (difference.RegistryKeys.Count != 0)
                    {
                        //todo v1 - determine the installer type and write it to the snapshot
                        //todo v1 - note keys passed in 
                        pkgInfo.RegistrySnapshot = difference;

                        var key = difference.RegistryKeys.FirstOrDefault();
                        if (key != null && key.HasQuietUninstall)
                        {
                            pkgInfo.HasSilentUninstall = true;
                        }
                    }
                }

                if (packageResult.Success)
                {
                    _shimgenService.install(config, packageResult);
                }
            }
            else
            {
                this.Log().Info(ChocolateyLoggers.Important, () => " Skipping Powershell and shimgen portions of the install due to non-Windows.");
            }

            _packageInfoService.save_package_information(pkgInfo);
            ensure_bad_package_path_is_clean(config, packageResult);

            if (!packageResult.Success)
            {
                this.Log().Error(ChocolateyLoggers.Important, "{0} {1} not successful.".format_with(packageResult.Name, commandName.to_string()));
                handle_unsuccessful_install(config, packageResult);

                return;
            }

            this.Log().Info(ChocolateyLoggers.Important, " {0} has been {1}ed successfully.".format_with(packageResult.Name, commandName.to_string()));
        }

        private IEnumerable<ChocolateyConfiguration> set_config_from_package_names_and_packages_config(ChocolateyConfiguration config, ConcurrentDictionary<string, PackageResult> packageInstalls)
        {
            // if there are any .config files, split those off of the config. Then return the config without those package names.
            foreach (var packageConfigFile in config.PackageNames.Split(new[] {ApplicationParameters.PackageNamesSeparator}, StringSplitOptions.RemoveEmptyEntries).or_empty_list_if_null().Where(p => p.Contains(".config")).ToList())
            {
                config.PackageNames = config.PackageNames.Replace(packageConfigFile, string.Empty);

                foreach (var packageConfig in get_packages_from_config(packageConfigFile, config, packageInstalls).or_empty_list_if_null())
                {
                    yield return packageConfig;
                }
            }

            yield return config;
        }

        private IEnumerable<ChocolateyConfiguration> get_packages_from_config(string packageConfigFile, ChocolateyConfiguration config, ConcurrentDictionary<string, PackageResult> packageInstalls)
        {
            IList<ChocolateyConfiguration> packageConfigs = new List<ChocolateyConfiguration>();

            if (!_fileSystem.file_exists(_fileSystem.get_full_path(packageConfigFile)))
            {
                var logMessage = "Could not find '{0}' in the location specified.".format_with(packageConfigFile);
                this.Log().Error(ChocolateyLoggers.Important, logMessage);
                var results = packageInstalls.GetOrAdd(packageConfigFile, new PackageResult(packageConfigFile, null, null));
                results.Messages.Add(new ResultMessage(ResultType.Error, logMessage));

                return packageConfigs;
            }

            var settings = _xmlService.deserialize<PackagesConfigFileSettings>(_fileSystem.get_full_path(packageConfigFile));
            foreach (var pkgSettings in settings.Packages.or_empty_list_if_null())
            {
                if (!pkgSettings.Disabled)
                {
                    var packageConfig = config.deep_copy();
                    packageConfig.PackageNames = pkgSettings.Id;
                    packageConfig.Sources = string.IsNullOrWhiteSpace(pkgSettings.Source) ? packageConfig.Sources : pkgSettings.Source;
                    packageConfig.Version = pkgSettings.Version;
                    packageConfig.InstallArguments = string.IsNullOrWhiteSpace(pkgSettings.InstallArguments) ? packageConfig.InstallArguments : pkgSettings.InstallArguments;
                    packageConfig.PackageParameters = string.IsNullOrWhiteSpace(pkgSettings.PackageParameters) ? packageConfig.PackageParameters : pkgSettings.PackageParameters;
                    if (pkgSettings.ForceX86) packageConfig.ForceX86 = true;
                    if (pkgSettings.AllowMultipleVersions) packageConfig.AllowMultipleVersions = true;
                    if (pkgSettings.IgnoreDependencies) packageConfig.IgnoreDependencies = true;
             
                    packageConfigs.Add(packageConfig);
                }
            }

            return packageConfigs;
        }

        public void handle_package_uninstall(PackageResult packageResult, ChocolateyConfiguration config)
        {
            if (!_fileSystem.directory_exists(packageResult.InstallLocation))
            {
                packageResult.InstallLocation += ".{0}".format_with(packageResult.Package.Version.to_string());
            }

            _shimgenService.uninstall(config, packageResult);

            if (!config.SkipPackageInstallProvider)
            {
                _powershellService.uninstall(config, packageResult);
            }

            _autoUninstallerService.run(packageResult, config);

            if (packageResult.Success)
            {
                //todo: v2 clean up package information store for things no longer installed (call it compact?)
                _packageInfoService.remove_package_information(packageResult.Package);
            }

            //todo:prevent reboots
        }

        private void ensure_bad_package_path_is_clean(ChocolateyConfiguration config, PackageResult packageResult)
        {
            try
            {
                string badPackageInstallPath = packageResult.InstallLocation.Replace(ApplicationParameters.PackagesLocation, ApplicationParameters.PackageFailuresLocation);
                if (_fileSystem.directory_exists(badPackageInstallPath))
                {
                    _fileSystem.delete_directory(badPackageInstallPath, recursive: true);
                }
            }
            catch (Exception ex)
            {
                if (config.Debug)
                {
                    this.Log().Error(() => "Attempted to delete bad package install path if existing. Had an error:{0}{1}".format_with(Environment.NewLine, ex));
                }
                else
                {
                    this.Log().Error(() => "Attempted to delete bad package install path if existing. Had an error:{0}{1}".format_with(Environment.NewLine, ex.Message));
                }
            }
        }

        private void handle_unsuccessful_install(ChocolateyConfiguration config, PackageResult packageResult)
        {
            foreach (var message in packageResult.Messages.Where(m => m.MessageType == ResultType.Error))
            {
                this.Log().Error(message.Message);
            }

            move_bad_package_to_failure_location(packageResult);
            rollback_previous_version(config, packageResult);
        }

        private void move_bad_package_to_failure_location(PackageResult packageResult)
        {
            _fileSystem.create_directory_if_not_exists(ApplicationParameters.PackageFailuresLocation);

            _fileSystem.move_directory(packageResult.InstallLocation, packageResult.InstallLocation.Replace(ApplicationParameters.PackagesLocation, ApplicationParameters.PackageFailuresLocation));
            _fileSystem.delete_directory(packageResult.InstallLocation, recursive: true);
        }

        private void rollback_previous_version(ChocolateyConfiguration config, PackageResult packageResult)
        {
            var rollbackDirectory = packageResult.InstallLocation + ApplicationParameters.RollbackPackageSuffix;
            if (!_fileSystem.directory_exists(rollbackDirectory)) return;

            var rollback = true;
            if (config.PromptForConfirmation)
            {
                var selection = InteractivePrompt.prompt_for_confirmation(" Unsuccessful install of {0}.{1}  Do you want to rollback to previous version (package files only)?".format_with(packageResult.Name, Environment.NewLine), new[] {"yes", "no"}, "yes", requireAnswer: true);
                if (selection.is_equal_to("no")) rollback = false;
            }

            if (rollback)
            {
                _fileSystem.move_directory(rollbackDirectory, packageResult.InstallLocation);
            }

            try
            {
                _fileSystem.delete_directory_if_exists(rollbackDirectory, recursive: true);
            }
            catch (Exception ex)
            {
                this.Log().Warn("Attempted to remove '{0}' but had an error:{1} {2}".format_with(rollbackDirectory, Environment.NewLine, ex.Message));
            }
        }
    }
}