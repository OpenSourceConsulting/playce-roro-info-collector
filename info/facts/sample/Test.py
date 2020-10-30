# -*- coding: utf-8 -*-
import sys
import abc

if sys.version_info >= (3, 4):
  ABC = abc.ABC
else:
  ABC = abc.ABCMeta('ABC', (), {})


class AbstractOsci(ABC):

  name = 'hoon'
  population = '100'
  capital = 'korea'

  @abc.abstractmethod
  def show(self):
    pass

  def nonshow(self):
    print('adpsd')


class Korea(AbstractOsci):

  def __init__(self, name, population, capital):
    self.name = name
    self.population = population
    self.capital = capital

  def show(self):
    print('dddd ', self.name)



a = Korea('a','a','a')
a.nonshow()

