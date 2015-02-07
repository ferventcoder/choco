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
    using System.Text.RegularExpressions;
    using configuration;
    using domain;
    using infrastructure.commands;
    using logging;
    using results;
    
    //todo this is the old nuget.exe installer code that needs cleaned up for webpi
    public class WebPiService : ISourceRunner
    {
        private readonly ICommandExecutor _commandExecutor;
        private readonly INugetService _nugetService;
        private const string PACKAGE_NAME_TOKEN = "{{packagename}}";
        private readonly string _webPiExePath = "webpicmd"; //ApplicationParameters.Tools.NugetExe;
        private readonly IDictionary<string, ExternalCommandArgument> _webPiListArguments = new Dictionary<string, ExternalCommandArgument>(StringComparer.InvariantCultureIgnoreCase);
        private readonly IDictionary<string, ExternalCommandArgument> _webPiInstallArguments = new Dictionary<string, ExternalCommandArgument>(StringComparer.InvariantCultureIgnoreCase);

        public WebPiService(ICommandExecutor commandExecutor, INugetService nugetService)
        {
            _commandExecutor = commandExecutor;
            _nugetService = nugetService;
            set_cmd_args_dictionaries();
        }

        /// <summary>
        ///   Set any command arguments dictionaries necessary for the service
        /// </summary>
        private void set_cmd_args_dictionaries()
        {
            //set_webpi_list_dictionary();
            set_webpi_install_dictionary();
        }

        /// <summary>
        ///   Sets webpicmd install dictionary
        /// </summary>
        private void set_webpi_install_dictionary()
        {
            _webPiInstallArguments.Add("_install_", new ExternalCommandArgument {ArgumentOption = "install", Required = true});
            _webPiInstallArguments.Add("_package_name_", new ExternalCommandArgument {ArgumentOption = PACKAGE_NAME_TOKEN, Required = true});
            _webPiInstallArguments.Add("Version", new ExternalCommandArgument {ArgumentOption = "-version ",});
            _webPiInstallArguments.Add("_output_directory_", new ExternalCommandArgument
                {
                    ArgumentOption = "-outputdirectory ",
                    ArgumentValue = "{0}".format_with(ApplicationParameters.PackagesLocation),
                    QuoteValue = true,
                    Required = true
                });
            _webPiInstallArguments.Add("Sources", new ExternalCommandArgument {ArgumentOption = "-source ", QuoteValue = true});
            _webPiInstallArguments.Add("Prerelease", new ExternalCommandArgument {ArgumentOption = "-prerelease"});
            _webPiInstallArguments.Add("_non_interactive_", new ExternalCommandArgument {ArgumentOption = "-noninteractive", Required = true});
            _webPiInstallArguments.Add("_no_cache_", new ExternalCommandArgument {ArgumentOption = "-nocache", Required = true});
        }

        public SourceType SourceType
        {
            get { return SourceType.webpi; }
        }

        public void ensure_source_app_installed(ChocolateyConfiguration config, Action<PackageResult> ensureAction)
        {
            var runnerConfig = new ChocolateyConfiguration()
            {
                PackageNames = ApplicationParameters.SourceRunner.WebPiPackage,
                Sources = ApplicationParameters.PackagesLocation,
                Debug = config.Debug,
                Force = config.Force,
                Verbose = config.Verbose,
                CommandExecutionTimeoutSeconds = config.CommandExecutionTimeoutSeconds,
                CacheLocation = config.CacheLocation,
                RegularOuptut = config.RegularOuptut,
            };
            runnerConfig.ListCommand.LocalOnly = true;

            var localPackages = _nugetService.list_run(runnerConfig, logResults: false);

            if (!localPackages.ContainsKey(ApplicationParameters.SourceRunner.WebPiPackage))
            {
                runnerConfig.Sources = ApplicationParameters.ChocolateyCommunityFeedSource;
                
                _nugetService.install_run(runnerConfig, ensureAction.Invoke);
            }
        }

        public void list_noop(ChocolateyConfiguration config)
        {
            
        }

        public ConcurrentDictionary<string, PackageResult> list_run(ChocolateyConfiguration config, bool logResults)
        {
            return new ConcurrentDictionary<string, PackageResult>();
        }

        public void install_noop(ChocolateyConfiguration config, Action<PackageResult> continueAction)
        {
        }

        public ConcurrentDictionary<string, PackageResult> install_run(ChocolateyConfiguration configuration, Action<PackageResult> continueAction)
        {
            var packageInstalls = new ConcurrentDictionary<string, PackageResult>();

            var args = ExternalCommandArgsBuilder.build_arguments(configuration, _webPiInstallArguments);

            foreach (var packageToInstall in configuration.PackageNames.Split(new[] {' '}, StringSplitOptions.RemoveEmptyEntries))
            {
                var argsForPackage = args.Replace(PACKAGE_NAME_TOKEN, packageToInstall);
                var exitCode = _commandExecutor.execute(
                    _webPiExePath, argsForPackage, configuration.CommandExecutionTimeoutSeconds,
                    (s, e) =>
                        {
                            var logMessage = e.Data;
                            if (string.IsNullOrWhiteSpace(logMessage)) return;
                            this.Log().Debug(() => " [WebPI] {0}".format_with(logMessage));

                            var packageName = get_value_from_output(logMessage, ApplicationParameters.OutputParser.Nuget.PackageName, ApplicationParameters.OutputParser.Nuget.PACKAGE_NAME_GROUP);
                            var packageVersion = get_value_from_output(logMessage, ApplicationParameters.OutputParser.Nuget.PackageVersion, ApplicationParameters.OutputParser.Nuget.PACKAGE_VERSION_GROUP);

                            if (ApplicationParameters.OutputParser.Nuget.ResolvingDependency.IsMatch(logMessage))
                            {
                                return;
                            }

                            var results = packageInstalls.GetOrAdd(packageName, new PackageResult(packageName, packageVersion, _webPiInstallArguments["_output_directory_"].ArgumentValue));

                            if (ApplicationParameters.OutputParser.Nuget.NotInstalled.IsMatch(logMessage))
                            {
                                this.Log().Error("{0} not installed: {1}".format_with(packageName, logMessage));
                                results.Messages.Add(new ResultMessage(ResultType.Error, logMessage));

                                return;
                            }

                            if (ApplicationParameters.OutputParser.Nuget.Installing.IsMatch(logMessage))
                            {
                                return;
                            }

                            if (string.IsNullOrWhiteSpace(packageName)) return;

                            this.Log().Info(ChocolateyLoggers.Important, "{0} {1}".format_with(packageName, !string.IsNullOrWhiteSpace(packageVersion) ? "v" + packageVersion : string.Empty));

                            if (ApplicationParameters.OutputParser.Nuget.AlreadyInstalled.IsMatch(logMessage) && !configuration.Force)
                            {
                                results.Messages.Add(new ResultMessage(ResultType.Inconclusive, packageName));
                                this.Log().Warn(" Already installed.");
                                this.Log().Warn(ChocolateyLoggers.Important, " Use -force if you want to reinstall.".format_with(Environment.NewLine));
                                return;
                            }

                            results.Messages.Add(new ResultMessage(ResultType.Debug, ApplicationParameters.Messages.ContinueChocolateyAction));
                            if (continueAction != null)
                            {
                                continueAction.Invoke(results);
                            }
                        },
                    (s, e) =>
                        {
                            if (string.IsNullOrWhiteSpace(e.Data)) return;
                            this.Log().Error(() => "{0}".format_with(e.Data));
                        }
                    );

                if (exitCode != 0)
                {
                    Environment.ExitCode = exitCode;
                }
            }
            return packageInstalls;
        }

        /// <summary>
        ///   Grabs a value from the output based on the regex.
        /// </summary>
        /// <param name="output">The output.</param>
        /// <param name="regex">The regex.</param>
        /// <param name="groupName">Name of the group.</param>
        /// <returns></returns>
        private static string get_value_from_output(string output, Regex regex, string groupName)
        {
            var matchGroup = regex.Match(output).Groups[groupName];
            if (matchGroup != null)
            {
                return matchGroup.Value;
            }

            return string.Empty;
        }
    }
}