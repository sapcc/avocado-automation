/******************************************************************************
*
*  Copyright 2021 SAP SE
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
*
******************************************************************************/

package server

import (
	"fmt"
	"io/ioutil"
	"path"
	"sync"

	"github.com/sapcc/vcf-automation/pkg/stack"
	"github.com/spf13/viper"
)

type Manager struct {
	controllers map[string]*StackController
	ProjectRoot string
	ConfigRoot  string
	sync.Mutex
}

type StackController struct {
	*stack.Controller
	ConfigPath string
	running    bool
	updCh      chan bool
	canCh      chan bool
}

func NewManager() *Manager {
	workdir := viper.GetString("work_dir")
	projectdir := viper.GetString("project_root")
	configdir := viper.GetString("config_dir")
	if projectdir == "" {
		projectdir = path.Join(workdir, "projects")
	}
	if configdir == "" {
		configdir = path.Join(workdir, "etc")
	}
	logger.Debugf("config directory: %s", configdir)
	logger.Debugf("project directory: %s", projectdir)
	return &Manager{
		ProjectRoot: projectdir,
		ConfigRoot:  configdir,
		controllers: make(map[string]*StackController),
	}
}

// New creates a new StackController from the config file (input full path). If
// there is already a controller in manager, an error is returned.
func (m *Manager) New(cfgpath string) (*StackController, error) {
	m.Lock()
	defer m.Unlock()
	cfg, err := stack.ReadConfig(cfgpath)
	if err != nil {
		return nil, err
	}
	pn, cn := cfg.GetProjectStackName()
	cfgName := fmt.Sprintf("%s-%s", pn, cn)
	if _, ok := m.controllers[cfgName]; ok {
		return nil, fmt.Errorf("controller already exists")
	}
	mc, err := stack.NewController(cfg, m.ProjectRoot)
	if err != nil {
		return nil, err
	}
	sc := &StackController{Controller: mc, ConfigPath: cfgpath}
	m.controllers[cfgName] = sc
	return sc, nil
}

// Get returns *StackController from manager by project type and stack name.
func (m *Manager) Get(project, stack string) (*StackController, bool) {
	m.Lock()
	defer m.Unlock()
	cfgName := fmt.Sprintf("%s-%s", project, stack)
	c, ok := m.controllers[cfgName]
	return c, ok
}

// Update updates *StackController in manager by project type and stack name.
// Error if controller does not exist.
func (m *Manager) Update(project, stack string) (*StackController, error) {
	m.Lock()
	defer m.Unlock()
	cfgName := fmt.Sprintf("%s-%s", project, stack)
	sc, ok := m.controllers[cfgName]
	if !ok {
		return nil, fmt.Errorf("controller not exist")
	}
	err := sc.reloadConfig()
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (m *Manager) ListConfigFiles() (cfgFiles []string, err error) {
	files, err := ioutil.ReadDir(manager.ConfigRoot)
	if err != nil {
		return
	}
	for _, f := range files {
		if !f.IsDir() {
			cfgFiles = append(cfgFiles, path.Join(m.ConfigRoot, f.Name()))
		}
	}
	return
}

func (m *Manager) ReloadConfigs() (messages []string) {
	messages = make([]string, 0)
	cfgFiles, err := manager.ListConfigFiles()
	if err != nil {
		logger.Errorf("list config files failed: %v", err)
		return
	}
	for _, fpath := range cfgFiles {
		cfg, err := stack.ReadConfig(fpath)
		if err != nil {
			err = fmt.Errorf("read config %s: %v", fpath, err)
			messages = append(messages, err.Error())
			logger.Error(err)
			continue
		}
		project, stack := cfg.GetProjectStackName()
		if _, ok := manager.Get(project, stack); !ok {
			// create new controller
			_, err := manager.New(fpath)
			msg := fmt.Sprintf("create controller from config %s", fpath)
			if err != nil {
				err = fmt.Errorf("%s: %v", msg, err)
				messages = append(messages, err.Error())
				logger.Error(err)
				continue
			} else {
				messages = append(messages, msg)
				logger.Println(msg)
			}
			//Do not start pulumi on a pod restart automatically!
			//nc.start()
		} else {
			// update controller
			nc, err := manager.Update(project, stack)
			msg := fmt.Sprintf("update controller from config %s", fpath)
			if err != nil {
				err = fmt.Errorf("%s: %v", msg, err)
				messages = append(messages, err.Error())
				logger.Error(err)
				continue
			} else {
				messages = append(messages, msg)
				logger.Println(msg)
			}
			nc.triggerUpdateStack()
		}
	}
	// delete non exist controller
	newFiles := make(map[string]struct{})
	for _, f := range cfgFiles {
		newFiles[f] = struct{}{}
	}
	for cfgName, c := range m.controllers {
		if _, ok := newFiles[c.ConfigPath]; !ok {
			c.stop()
			delete(m.controllers, cfgName)
			msg := fmt.Sprintf("controller %s deleted", cfgName)
			messages = append(messages, msg)
			logger.Println(msg)
		}
	}
	return
}

func (c *StackController) reloadConfig() error {
	return c.Controller.ReloadConfig(c.ConfigPath)
}

func (c *StackController) start() {
	if c.updCh == nil {
		c.updCh = make(chan bool)
	}
	if c.canCh == nil {
		c.canCh = make(chan bool)
	}
	c.running = true
	go c.Controller.Run(c.updCh, c.canCh)
}

func (c *StackController) stop() {
	c.running = false
	go func() {
		c.canCh <- true
	}()
}

func (c *StackController) triggerUpdateStack() {
	go func() {
		c.updCh <- true
	}()
}
