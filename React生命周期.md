# React生命周期

## 挂载（Mounting）

组件实例被创建并插入`DOM`中时

- constructor
  
  **如果不初始化`state`或不进行方法绑定，则不需要为组件实现`constructor`**

  在组件挂载之前，会调用它的`constructor`。在为`class`组件实现`constructor`时，应该在其他语句之前调用`super(props)`，用于初始化`this`，否则可能会出现`this.props`未定义的bug。
  `constructor`通常只用于以下两种情况：
  
  - 初始化内部`state`
  - 为事件处理函数绑定`this`
  
- static getDerivedStateFromProps
  
  **`static getDerivedStateFromProps`的存在只有一个目的：让组件在`props`变化时更新`state`**

- render
  
  `render`

- componentDidMount
  
  `componentDidMount`会在组件挂载后立即调用。

## 更新（Updating）

组件的`props`或`state`发生变化时会触发更新

- static getDerivedStateFromProps
  
  **`static getDerivedStateFromProps`的存在只有一个目的：让组件在`props`变化时更新`state`**

- shouldComponentUpdate
  
  `shouldComponentUpdate`

- render
  
  `render`

- getSnapshotBeforeUpdate
  
  `getSnapshotBeforeUpdate`

- componentDidUpdate
  
  `componentDidUpdate`会在组件更新后调用，首次渲染不会执行

## 卸载（Unmounting）

组件从`DOM`中移除时

- componentWillUnmount

## 错误边界

- static getDerivedStateFromError

- componentDidCatch